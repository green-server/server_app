package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	serverName  = "greenserver"
	approveTool = "mcp__" + serverName + "__approve"

	consultTimeout = 2 * time.Hour

	// Claude Code's own limit on one MCP call. It must outlast the 10 minute
	// approval window, or a slow human would look like a failed tool.
	mcpToolTimeoutMS = "660000"

	hookTimeoutSeconds = 660
)

// Bash and Read are the only built-in tools Claude gets. Edit and Write are
// left out on purpose: every change then goes through Bash, where it is
// classified and can carry an undo comment. Grep and Glob are out because a
// recursive search reads files the classifier never sees named.
const availableTools = "Bash,Read"

// allowedTools is the first layer and only lets plain reads skip the prompt
// tool. Commands with a mutating spelling (journalctl --vacuum, nvidia-smi -pl,
// ss -K) are listed narrowly or not at all; a read left out here still runs,
// because the prompt tool allows anything the classifier calls auto.
var allowedTools = []string{
	"Read",
	"Bash(ps *)", "Bash(systemctl status *)", "Bash(journalctl -u *)",
	"Bash(nvidia-smi -q*)", "Bash(nvidia-smi --query*)",
	"Bash(cat *)", "Bash(head *)", "Bash(tail *)", "Bash(ls *)", "Bash(df *)", "Bash(du *)",
	"Bash(free *)", "Bash(uptime *)", "Bash(uname *)", "Bash(lscpu *)", "Bash(lsblk *)",
}

var disallowedTools = []string{
	"Edit", "Write", "NotebookEdit", "WebFetch", "WebSearch", "Task", "Agent", "Grep", "Glob",
	"Bash(rm -rf *)", "Bash(rm -fr *)", "Bash(dd *)", "Bash(ssh *)", "Bash(scp *)",
	"Bash(ufw *)", "Bash(iptables *)", "Bash(nft *)", "Bash(eval *)", "Bash(env *)", "Bash(printenv *)",
	"Read(**/.env)", "Read(**/.env.*)", "Read(**/id_rsa*)", "Read(**/id_ed25519*)", "Read(**/.ssh/**)",
	"Read(/etc/shadow)", "Read(**/credentials)", "Read(/proc/*/environ)",
}

// models is the list the backend offers. The value reaches claude's argv, so
// anything else is refused instead of being passed through.
var models = map[string]bool{
	"claude-fable-5-1": true, "claude-opus-5-5": true, "claude-sonnet-5-5": true, "claude-haiku-5-5": true,
}

// levels are the server states the final answer may report.
var levels = map[string]bool{"good": true, "fair": true, "warning": true, "critical": true}

func (a *Agent) startConsultation(ctx context.Context, m incoming) {
	fail := func(summary string) {
		a.sendReliable(consultationStatusMsg{Type: "consultation_status", ConsultationID: m.ConsultationID, Status: "failed", Summary: summary})
	}
	if m.AuthMode != "subscription" && m.AuthMode != "api_key" {
		fail("지원하지 않는 인증 방식입니다")
		return
	}
	if m.MaxTurns <= 0 {
		fail("maxTurns가 올바르지 않습니다")
		return
	}
	if !models[m.Model] {
		fail("지원하지 않는 모델입니다")
		return
	}
	cctx, cancel := context.WithTimeout(ctx, consultTimeout)
	a.mu.Lock()
	if a.active != nil {
		a.mu.Unlock()
		cancel()
		fail("이미 실행 중인 컨설팅이 있습니다")
		return
	}
	a.active = &consultation{m.ConsultationID, cctx}
	a.mu.Unlock()

	go func() {
		defer func() {
			a.mu.Lock()
			a.active = nil
			clear(a.useIDs)
			clear(a.granted)
			a.mu.Unlock()
			cancel()
		}()
		a.sendReliable(consultationStatusMsg{Type: "consultation_status", ConsultationID: m.ConsultationID, Status: "running"})
		res, err := a.invokeClaude(cctx, m)
		if err != nil {
			log.Printf("consultation %d failed: %v", m.ConsultationID, err)
			fail("컨설팅을 완료하지 못했습니다")
			return
		}
		a.sendReliable(consultationStatusMsg{
			Type: "consultation_status", ConsultationID: m.ConsultationID, Status: "done",
			Summary: res.Summary, Level: res.Level, Feedback: res.Feedback, Fixes: res.Fixes,
			Recommendations: res.Recommendations,
		})
	}()
}

func (a *Agent) invokeClaude(ctx context.Context, m incoming) (*consultResult, error) {
	bin, err := exec.LookPath("claude")
	if err != nil {
		return nil, err
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	work := filepath.Join(a.cfg.StateDir, "work")
	if err := os.MkdirAll(work, 0o700); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, bin, claudeArgs(m.Model, m.MaxTurns, exe, SocketPath(a.cfg.StateDir))...)
	cmd.Dir = work
	cmd.Env = childEnv(os.Environ(), m.AuthMode)
	cmd.Stdin = strings.NewReader(buildPrompt(a.cfg.StateDir))
	cmd.Stderr = os.Stderr
	// Own process group, so a timeout also ends whatever Claude started.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 5 * time.Second
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	res, parseErr := parseStream(stdout)
	waitErr := cmd.Wait()
	if parseErr != nil {
		return nil, errors.Join(parseErr, waitErr)
	}
	return res, waitErr
}

func claudeArgs(model string, maxTurns int, exe, socket string) []string {
	hook := func(kind string) []map[string]any {
		command := fmt.Sprintf("%s hook %s --socket %s", shellQuote(exe), kind, shellQuote(socket))
		return []map[string]any{{"matcher": "*", "hooks": []map[string]any{
			// The pre hook waits for the web decision, so it must outlast the approval window.
			{"type": "command", "command": command, "timeout": hookTimeoutSeconds},
		}}}
	}
	settings := mustJSON(map[string]any{"hooks": map[string]any{
		"PreToolUse":  hook("pre"),
		"PostToolUse": hook("post"),
		// A command that fails fires this one instead of PostToolUse.
		"PostToolUseFailure": hook("post"),
	}})
	mcp := mustJSON(map[string]any{"mcpServers": map[string]any{
		serverName: map[string]any{"command": exe, "args": []string{"mcp-approve", "--socket", socket}},
	}})
	return []string{
		"-p",
		"--output-format", "stream-json",
		"--verbose", // claude refuses stream-json under -p without it
		"--model", model,
		// Always auto. The hooks enforce the tiers whatever this mode decides.
		"--permission-mode", "auto",
		"--max-turns", fmt.Sprint(maxTurns),
		"--tools", availableTools,
		"--allowedTools", strings.Join(allowedTools, ","),
		"--disallowedTools", strings.Join(disallowedTools, ","),
		"--permission-prompt-tool", approveTool,
		"--settings", settings,
		"--mcp-config", mcp,
		"--strict-mcp-config",
	}
}

func mustJSON(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(data)
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// childEnv passes Claude's environment through by name only. The agent token
// never reaches Claude. In subscription mode the API key variables must go,
// or claude would bill the key instead of using the owner's login.
func childEnv(environ []string, authMode string) []string {
	drop := map[string]bool{"GREENSERVER_TOKEN": true, "MCP_TOOL_TIMEOUT": true}
	if authMode != "api_key" {
		drop["ANTHROPIC_API_KEY"] = true
		drop["ANTHROPIC_AUTH_TOKEN"] = true
	}
	out := make([]string, 0, len(environ)+1)
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if !drop[name] {
			out = append(out, kv)
		}
	}
	return append(out, "MCP_TOOL_TIMEOUT="+mcpToolTimeoutMS)
}

func buildPrompt(stateDir string) string {
	return strings.ReplaceAll(promptTemplate, "{{METRICS}}", latestPath(stateDir))
}

const promptTemplate = `당신은 이 서버 안에서 실행 중인 Green Server 전력 컨설턴트입니다. 이 서버의 전력 낭비를 진단하고, 승인을 받아 조치한 뒤 결과를 보고하세요.

최신 측정값은 {{METRICS}} 파일에 있고 10초마다 갱신됩니다. isEstimated가 true면 실측이 아니라 추정값이며, 그렇게 표시해서 보고하세요.

## 컨설팅 가이드라인

- 측정한 데이터만 근거로 판단합니다. 추측으로 절약액을 말하지 않습니다.
- 변경 전에 백업하고, 모든 조치에 되돌리는 명령어를 기록합니다.
- 한 번에 하나씩 바꾸고 재측정합니다. 효과가 없으면 되돌립니다.
- 서비스 가용성이 우선입니다. 접속자가 있으면 중지하지 않습니다.
- 결과는 JSON으로 반환합니다.

## 명령 실행 규칙

쓸 수 있는 도구는 Bash와 Read뿐입니다. 파일 수정도 Bash로 합니다.

읽기 명령은 바로 실행됩니다. 상태를 바꾸는 명령은 웹에서 사람이 승인해야 실행됩니다. 이런 명령은 맨 끝에 되돌리는 명령을 주석으로 붙이세요. 없으면 승인 요청 없이 거부됩니다.

    sudo -n systemctl stop minecraft # undo: sudo -n systemctl start minecraft

되돌리는 명령은 실제로 상태를 복구하는 명령이어야 합니다. true나 echo는 거부됩니다. 설정 파일은 백업과 수정을 한 줄에서 하세요.

    cp app.conf app.conf.bak && sed -i 's/a/b/' app.conf # undo: cp app.conf.bak app.conf

- 쉘 변수와 명령 치환 대신 값을 직접 쓰세요. 값을 정적으로 확인할 수 없는 명령은 거부됩니다.
- 비밀 파일, rm -rf, dd, 파이프로 쉘 실행, SSH와 방화벽 변경은 항상 금지이며 우회를 시도하지 마세요.
- sudo는 비밀번호 없이 허용된 명령만 됩니다. sudo -l로 확인하세요.
- 거부되면 같은 명령을 다시 시도하지 말고 다른 방법을 찾거나 보고서에 남기세요.

## 최종 응답

마지막 응답은 다른 글 없이 아래 형식의 JSON 하나만 출력하세요. 글은 모두 한국어로 간결하게 씁니다.

{"level":"good","summary":"한 문장 요약","feedback":["측정값을 근거로 한 짧은 피드백"],"fixes":["해결 단계"],"recommendations":[{"type":"idle","detail":"무엇을 왜 권하는지","estSavingKrw":0}]}

level은 현재 서버 상태입니다.

- good: 낭비나 이상이 없습니다.
- fair: 줄일 여지가 조금 있습니다.
- warning: 낭비가 크거나 장애 위험 징후가 있습니다.
- critical: 폭주 프로세스, 과열, 디스크나 메모리 고갈처럼 바로 조치해야 합니다.

feedback은 최대 5개이고 항목마다 한 문장입니다. fixes는 level이 warning이나 critical일 때 서버 주인이 순서대로 따라 할 해결 단계를 쓰고, 그 외에는 빈 배열로 둡니다.

type은 idle, empty_game_server, oversized, night_stop, runaway_process 중에서 고르고, 맞는 것이 없으면 짧은 영어 snake_case를 씁니다. estSavingKrw는 측정값으로 계산한 월 절약 예상액(원)입니다.`

type consultResult struct {
	Level           string           `json:"level"`
	Summary         string           `json:"summary"`
	Feedback        []string         `json:"feedback"`
	Fixes           []string         `json:"fixes"`
	Recommendations []recommendation `json:"recommendations"`
}

// parseStream reads claude's stream-json output and decodes the final answer.
// Lines before the result event are progress; the hooks record what matters.
func parseStream(r io.Reader) (*consultResult, error) {
	var final *struct {
		IsError bool   `json:"is_error"`
		Subtype string `json:"subtype"`
		Result  string `json:"result"`
	}
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 64*1024), 64<<20)
	for s.Scan() {
		var ev struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(s.Bytes(), &ev) != nil || ev.Type != "result" {
			continue
		}
		if err := json.Unmarshal(s.Bytes(), &final); err != nil {
			return nil, fmt.Errorf("bad result event: %w", err)
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	switch {
	case final == nil:
		return nil, errors.New("claude produced no result event")
	case final.IsError || final.Subtype != "success":
		return nil, fmt.Errorf("claude ended with %q", final.Subtype)
	}
	var res consultResult
	if err := json.Unmarshal([]byte(extractJSON(final.Result)), &res); err != nil {
		return nil, fmt.Errorf("final answer is not the expected JSON: %w", err)
	}
	if strings.TrimSpace(res.Summary) == "" {
		return nil, errors.New("final answer has no summary")
	}
	if !levels[res.Level] {
		res.Level = "" // the run already cost tokens: keep the report, drop the bad field
	}
	return &res, nil
}

// extractJSON tolerates a code fence or a sentence around the object.
func extractJSON(text string) string {
	text = strings.TrimSpace(text)
	if json.Valid([]byte(text)) {
		return text
	}
	start, end := strings.IndexByte(text, '{'), strings.LastIndexByte(text, '}')
	if start < 0 || end < start {
		return text
	}
	return text[start : end+1]
}
