package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/green-server/server_app/internal/classify"
	"github.com/green-server/server_app/internal/metrics"
)

// fakeBackend stands in for the Express server.
type fakeBackend struct {
	t     *testing.T
	srv   *httptest.Server
	msgs  chan map[string]any
	conns chan *websocket.Conn
	auth  chan string
	url   string
}

func newBackend(t *testing.T) *fakeBackend {
	b := &fakeBackend{t: t, msgs: make(chan map[string]any, 256), conns: make(chan *websocket.Conn, 8), auth: make(chan string, 8)}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		b.auth <- r.Header.Get("Authorization")
		b.conns <- c
		for {
			_, data, err := c.Read(context.Background())
			if err != nil {
				return
			}
			var m map[string]any
			if json.Unmarshal(data, &m) == nil {
				b.msgs <- m
			}
		}
	}))
	t.Cleanup(b.srv.Close)
	b.url = "ws" + strings.TrimPrefix(b.srv.URL, "http") + "/ws/agent"
	return b
}

func (b *fakeBackend) expect(kind string) map[string]any {
	b.t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case m := <-b.msgs:
			if m["type"] == kind {
				return m
			}
		case <-deadline:
			b.t.Fatalf("no %s message", kind)
		}
	}
}

func (b *fakeBackend) conn() *websocket.Conn {
	b.t.Helper()
	select {
	case c := <-b.conns:
		return c
	case <-time.After(5 * time.Second):
		b.t.Fatal("agent did not connect")
	}
	return nil
}

func tell(t *testing.T, c *websocket.Conn, v any) {
	t.Helper()
	data, _ := json.Marshal(v)
	if err := c.Write(context.Background(), websocket.MessageText, data); err != nil {
		t.Fatal(err)
	}
}

// Socket paths have a short OS limit, too short for t.TempDir on macOS.
func stateDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "gs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func newAgent(t *testing.T, url string) *Agent {
	t.Helper()
	a, err := New(Config{Server: url, Token: "tok-123", StateDir: stateDir(t), Profile: metrics.Profile{IdleWatts: 10, MaxWatts: 50}, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	a.metricsEvery = 20 * time.Millisecond
	a.backoffBase = 10 * time.Millisecond
	a.runUndo = func(context.Context, string) int {
		t.Error("undo must not run in this test")
		return 1
	}
	return a
}

func start(t *testing.T, a *Agent) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		a.Run(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

// connected starts the agent with a consultation open and no Claude involved.
func connected(t *testing.T) (*Agent, *fakeBackend, *websocket.Conn) {
	t.Helper()
	b := newBackend(t)
	a := newAgent(t, b.url)
	a.active = &consultation{7, context.Background()}
	start(t, a)
	c := b.conn()
	b.expect("hello")
	return a, b, c
}

func input(command string) json.RawMessage {
	data, _ := json.Marshal(map[string]string{"command": command})
	return data
}

type approval struct {
	resp ipcResponse
	err  error
}

func ask(a *Agent, id, command string) chan approval {
	ch := make(chan approval, 1)
	go func() {
		resp, err := call(SocketPath(a.cfg.StateDir), ipcRequest{Kind: kindApprove, Tool: "Bash", Input: input(command), ToolUseID: id})
		ch <- approval{resp, err}
	}()
	return ch
}

func result(t *testing.T, ch chan approval) ipcResponse {
	t.Helper()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatal(r.err)
		}
		return r.resp
	case <-time.After(5 * time.Second):
		t.Fatal("approval never finished")
	}
	return ipcResponse{}
}

const stopNginx = "sudo -n systemctl stop nginx # undo: sudo -n systemctl start nginx"

func TestHelloAuthAndMetrics(t *testing.T) {
	b := newBackend(t)
	start(t, newAgent(t, b.url))
	if got := <-b.auth; got != "Bearer tok-123" {
		t.Fatalf("auth header %q", got)
	}
	h := b.expect("hello")
	if h["agentVersion"] != "test" || h["hostname"] == "" || h["os"] == "" {
		t.Fatalf("%v", h)
	}
	m := b.expect("metrics")
	for _, key := range []string{"ts", "cpuPct", "memPct", "watts", "isEstimated", "processes"} {
		if _, ok := m[key]; !ok {
			t.Fatalf("metrics missing %s: %v", key, m)
		}
	}
	if m["isEstimated"] != true {
		t.Fatalf("no RAPL here, so this is an estimate: %v", m)
	}
	if _, err := time.Parse(time.RFC3339, m["ts"].(string)); err != nil {
		t.Fatal(err)
	}
}

func TestReconnectsAndSaysHelloAgain(t *testing.T) {
	b := newBackend(t)
	start(t, newAgent(t, b.url))
	c := b.conn()
	b.expect("hello")
	c.CloseNow()
	b.conn()
	b.expect("hello")
}

func TestBackoffGrowsAndCaps(t *testing.T) {
	var attempts atomic.Int32
	var times [8]atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n := attempts.Add(1); n <= 8 {
			times[n-1].Store(time.Now().UnixMilli())
		}
		http.Error(w, "nope", http.StatusUnauthorized)
	}))
	defer srv.Close()
	a := newAgent(t, "ws"+strings.TrimPrefix(srv.URL, "http"))
	a.backoffBase = 5 * time.Millisecond
	a.backoffMax = 40 * time.Millisecond
	start(t, a)
	deadline := time.Now().Add(5 * time.Second)
	for attempts.Load() < 8 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if attempts.Load() < 8 {
		t.Fatalf("only %d attempts", attempts.Load())
	}
	first, last := times[1].Load()-times[0].Load(), times[7].Load()-times[6].Load()
	if last <= first || last > 200 {
		t.Fatalf("gaps %dms then %dms: should grow, then stay near the cap", first, last)
	}
}

func TestEndpoint(t *testing.T) {
	good := map[string]string{
		"wss://api.example.com":           "wss://api.example.com/ws/agent",
		"wss://api.example.com/ws/agent":  "wss://api.example.com/ws/agent",
		"ws://localhost:4000/ws/agent":    "ws://localhost:4000/ws/agent",
		"ws://127.0.0.1:4000":             "ws://127.0.0.1:4000/ws/agent",
		"wss://api.example.com/custom/ws": "wss://api.example.com/custom/ws",
	}
	for in, want := range good {
		if got, err := endpoint(in); err != nil || got != want {
			t.Errorf("%s: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "ws://example.com", "ws://10.0.0.5:4000", "http://example.com", "example.com"} {
		if _, err := endpoint(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	cfg := Config{Server: "wss://x", StateDir: stateDir(t), Profile: metrics.Profile{MaxWatts: 10}}
	if _, err := New(cfg); err == nil {
		t.Fatal("missing token accepted")
	}
	cfg.Token, cfg.Profile = "t", metrics.Profile{IdleWatts: 50, MaxWatts: 10}
	if _, err := New(cfg); err == nil {
		t.Fatal("idle above max accepted")
	}
}

func TestSocketIsPrivate(t *testing.T) {
	b := newBackend(t)
	a := newAgent(t, b.url)
	start(t, a)
	b.conn()
	dirInfo, err := os.Stat(a.cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	sockInfo, err := os.Stat(SocketPath(a.cfg.StateDir))
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o700 || sockInfo.Mode().Perm() != 0o600 {
		t.Fatalf("dir %o, socket %o", dirInfo.Mode().Perm(), sockInfo.Mode().Perm())
	}
}

func TestNoUndoNeverReachesTheWeb(t *testing.T) {
	a, b, _ := connected(t)
	r := result(t, ask(a, "req-7", "systemctl stop nginx"))
	if r.Allow || !strings.Contains(r.Message, "undo") {
		t.Fatalf("%+v", r)
	}
	if m := b.expect("tool_call"); m["decision"] != "blocked" || m["tier"] != "approve" || m["undoCommand"] != nil {
		t.Fatalf("%v", m)
	}
}

func TestPromptToolDeniesDenyTier(t *testing.T) {
	a, b, _ := connected(t)
	if r := result(t, ask(a, "req-8", "rm -rf /tmp/x # undo: touch /tmp/x")); r.Allow {
		t.Fatalf("%+v", r)
	}
	if m := b.expect("tool_call"); m["decision"] != "blocked" || m["tier"] != "deny" {
		t.Fatalf("%v", m)
	}
}

func TestPromptToolAllowsAutoWithoutAsking(t *testing.T) {
	a, _, _ := connected(t)
	if r := result(t, ask(a, "req-9", "ps aux")); !r.Allow {
		t.Fatalf("%+v", r)
	}
}

func TestPromptToolRefusesOtherTools(t *testing.T) {
	a, _, _ := connected(t)
	resp, err := call(SocketPath(a.cfg.StateDir), ipcRequest{Kind: kindApprove, Tool: "Write", Input: json.RawMessage(`{"file_path":"/tmp/x"}`)})
	if err != nil || resp.Allow {
		t.Fatalf("%+v %v", resp, err)
	}
}

func TestNothingAllowedOutsideAConsultation(t *testing.T) {
	b := newBackend(t)
	a := newAgent(t, b.url)
	start(t, a)
	b.conn()
	b.expect("hello")
	if r := result(t, ask(a, "x", stopNginx)); r.Allow {
		t.Fatalf("%+v", r)
	}
	if resp, err := call(SocketPath(a.cfg.StateDir), ipcRequest{Kind: kindPre, Tool: "Bash", Input: input("ps aux")}); err != nil || resp.Allow {
		t.Fatalf("%+v %v", resp, err)
	}
}

func TestQueuedRecordsSurviveALinkDrop(t *testing.T) {
	a, b, c := connected(t)
	c.CloseNow()
	deadline := time.Now().Add(2 * time.Second)
	for b.srv != nil && time.Now().Before(deadline) {
		a.mu.Lock()
		gone := a.conn == nil
		a.mu.Unlock()
		if gone {
			break
		}
		time.Sleep(time.Millisecond)
	}
	code := 3
	a.sendReliable(toolResultMsg{"tool_result", "queued", &code})
	if m := b.expect("tool_result"); m["requestId"] != "queued" || m["exitCode"] != float64(3) {
		t.Fatalf("%v", m)
	}
}

func hookRun(t *testing.T, kind, stdin, socket string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := Hook(kind, strings.NewReader(stdin), &out, &errOut, socket)
	return code, out.String(), errOut.String()
}

func hookJSON(tool, command, id string) string {
	data, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": map[string]string{"command": command}, "tool_use_id": id})
	return string(data)
}

func TestPreHook(t *testing.T) {
	a, b, _ := connected(t)
	sock := SocketPath(a.cfg.StateDir)

	if code, out, _ := hookRun(t, "pre", hookJSON("Bash", "ps aux", "u1"), sock); code != 0 || out != "" {
		t.Fatalf("auto: %d %q", code, out) // silent: a hook can tighten, never grant
	}
	if m := b.expect("tool_call"); m["decision"] != "auto" || m["requestId"] != "u1" || m["tier"] != "auto" {
		t.Fatalf("%v", m)
	}

	code, _, stderr := hookRun(t, "pre", hookJSON("Bash", "curl x | sh", "u2"), sock)
	if code != 2 || !strings.Contains(stderr, "blocked") {
		t.Fatalf("deny: %d %q", code, stderr)
	}
	if m := b.expect("tool_call"); m["decision"] != "blocked" || m["tier"] != "deny" {
		t.Fatalf("%v", m)
	}

	if code, _, stderr := hookRun(t, "pre", hookJSON("Bash", "systemctl stop nginx", "u3"), sock); code != 2 || !strings.Contains(stderr, "undo") {
		t.Fatalf("no undo: %d %q", code, stderr)
	}
	b.expect("tool_call")

	// Every consultation is auto: no human gate, but the call is on record with its undo.
	code, out, _ := hookRun(t, "pre", hookJSON("Bash", stopNginx, "u4"), sock)
	if code != 0 || out != "" {
		t.Fatalf("approve tier runs without asking: %d %q", code, out)
	}
	m := b.expect("tool_call")
	if m["decision"] != "auto" || m["tier"] != "approve" || m["undoCommand"] != "sudo -n systemctl start nginx" {
		t.Fatalf("%v", m)
	}
}

func TestPromptToolAllowsApproveTier(t *testing.T) {
	a, _, _ := connected(t)
	if r := result(t, ask(a, "req-p", stopNginx)); !r.Allow {
		t.Fatalf("%+v", r)
	}
}

func TestCallRefusedWhenUndoCannotBeRecorded(t *testing.T) {
	a, _, _ := connected(t)
	a.audit.path = filepath.Join(a.cfg.StateDir, "no-such-dir", "audit.jsonl")
	code, _, stderr := hookRun(t, "pre", hookJSON("Bash", stopNginx, "u9"), SocketPath(a.cfg.StateDir))
	if code != 2 || !strings.Contains(stderr, "undo") {
		t.Fatalf("%d %q", code, stderr)
	}
}

func TestUndoRunsOnlyWhatWasRecorded(t *testing.T) {
	a, b, c := connected(t)
	var ran atomic.Pointer[string]
	a.runUndo = func(_ context.Context, command string) int {
		ran.Store(&command)
		return 4
	}
	if code, _, _ := hookRun(t, "pre", hookJSON("Bash", stopNginx, "req-u"), SocketPath(a.cfg.StateDir)); code != 0 {
		t.Fatal(code)
	}
	b.expect("tool_call")

	tell(t, c, map[string]any{"type": "undo", "toolCallId": 11, "command": "sudo -n systemctl start nginx"})
	if m := b.expect("undo_result"); m["toolCallId"] != float64(11) || m["exitCode"] != float64(4) {
		t.Fatalf("%v", m)
	}
	if got := ran.Load(); got == nil || *got != "sudo -n systemctl start nginx" {
		t.Fatalf("%v", got)
	}
}

func TestClaudeArgsForceAutoModeAndModel(t *testing.T) {
	args := strings.Join(claudeArgs("claude-opus-5-5", 5, "/bin/gs", "/tmp/s"), " ")
	for _, want := range []string{"--permission-mode auto", "--model claude-opus-5-5", "--permission-prompt-tool"} {
		if !strings.Contains(args, want) {
			t.Fatalf("missing %q in %s", want, args)
		}
	}
}

func TestUnknownModelRefused(t *testing.T) {
	b := newBackend(t)
	start(t, newAgent(t, b.url))
	c := b.conn()
	b.expect("hello")
	tell(t, c, map[string]any{"type": "consultation_start", "consultationId": 1, "authMode": "api_key", "model": "--dangerously-skip-permissions", "maxTurns": 5})
	if m := b.expect("consultation_status"); m["status"] != "failed" {
		t.Fatalf("%v", m)
	}
}

func TestPreHookFailsClosed(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "none.sock")
	for name, stdin := range map[string]string{
		"garbage":       "not json",
		"empty":         "",
		"no tool":       `{"tool_input":{"command":"ps aux"}}`,
		"unknown tool":  `{"tool_name":"Write","tool_input":{"file_path":"/tmp/x"}}`,
		"agent is down": hookJSON("Bash", "ps aux", "u"),
		"deny, no link": hookJSON("Bash", "rm -rf /", "u"),
	} {
		if code, _, _ := hookRun(t, "pre", stdin, missing); code != 2 {
			t.Errorf("%s: exit %d, want 2", name, code)
		}
	}
}

func TestPostHookRecordsSuccessAndFailure(t *testing.T) {
	a, b, _ := connected(t)
	sock := SocketPath(a.cfg.StateDir)
	ok := `{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"ps aux"},"tool_use_id":"p1","tool_response":{"stdout":"x"}}`
	if code, _, _ := hookRun(t, "post", ok, sock); code != 0 {
		t.Fatal(code)
	}
	if m := b.expect("tool_result"); m["requestId"] != "p1" || m["exitCode"] != float64(0) {
		t.Fatalf("%v", m)
	}
	failed := `{"hook_event_name":"PostToolUseFailure","tool_name":"Bash","tool_input":{"command":"false"},"tool_use_id":"p2","error":"Exit code 3\nboom"}`
	hookRun(t, "post", failed, sock)
	if m := b.expect("tool_result"); m["requestId"] != "p2" || m["exitCode"] != float64(3) {
		t.Fatalf("%v", m)
	}
	unknown := `{"hook_event_name":"PostToolUseFailure","tool_name":"Bash","tool_input":{"command":"x"},"tool_use_id":"p3","error":"interrupted"}`
	hookRun(t, "post", unknown, sock)
	if m := b.expect("tool_result"); m["requestId"] != "p3" || m["exitCode"] != nil {
		t.Fatalf("%v", m)
	}
	data, err := os.ReadFile(filepath.Join(a.cfg.StateDir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"p1", "p2", "p3"} {
		if !strings.Contains(string(data), `"requestId":"`+id+`"`) {
			t.Fatalf("%s not in audit log:\n%s", id, data)
		}
	}
}

func mcpExchange(t *testing.T, socket string, lines ...string) []map[string]any {
	t.Helper()
	var out bytes.Buffer
	if err := ServeMCP(strings.NewReader(strings.Join(lines, "\n")+"\n"), &out, socket); err != nil {
		t.Fatal(err)
	}
	var got []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("stdout must be pure JSON-RPC: %q", line)
		}
		got = append(got, m)
	}
	return got
}

func TestMCPHandshake(t *testing.T) {
	got := mcpExchange(t, "/nonexistent",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":4,"method":"resources/list"}`,
	)
	if len(got) != 4 {
		t.Fatalf("%v", got)
	}
	if got[0]["result"].(map[string]any)["protocolVersion"] != "2025-06-18" {
		t.Fatalf("%v", got[0])
	}
	tools := got[1]["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 1 || tools[0].(map[string]any)["name"] != "approve" {
		t.Fatalf("%v", tools)
	}
	if got[3]["error"] == nil {
		t.Fatalf("%v", got[3])
	}
	if approveTool != "mcp__greenserver__approve" {
		t.Fatal(approveTool)
	}
}

func mcpDecision(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	content := m["result"].(map[string]any)["content"].([]any)
	if len(content) != 1 {
		t.Fatalf("claude expects a single text block: %v", content)
	}
	block := content[0].(map[string]any)
	var d map[string]any
	if block["type"] != "text" || json.Unmarshal([]byte(block["text"].(string)), &d) != nil {
		t.Fatalf("%v", block)
	}
	return d
}

func mcpCall(tool, command string) string {
	data, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{
		"name": "approve", "arguments": map[string]any{"tool_name": tool, "input": map[string]string{"command": command}, "tool_use_id": "m1"},
	}})
	return string(data)
}

func TestMCPAllowReturnsInputUnchanged(t *testing.T) {
	a, _, _ := connected(t)
	d := mcpDecision(t, mcpExchange(t, SocketPath(a.cfg.StateDir), mcpCall("Bash", "ps aux"))[0])
	if d["behavior"] != "allow" || d["updatedInput"].(map[string]any)["command"] != "ps aux" {
		t.Fatalf("%v", d)
	}
}

func TestMCPDeniesWhenAgentIsGone(t *testing.T) {
	d := mcpDecision(t, mcpExchange(t, filepath.Join(t.TempDir(), "none"), mcpCall("Bash", "ps aux"))[0])
	if d["behavior"] != "deny" || d["message"] == "" {
		t.Fatalf("%v", d)
	}
}

// The backend is not trusted to choose what runs on the server.
func TestUndoRefusesWhatWasNotRecorded(t *testing.T) {
	a, b, c := connected(t)
	a.runUndo = func(context.Context, string) int {
		t.Error("refused undo was executed")
		return 0
	}
	blocked := "rm -rf /srv # undo: sudo -n systemctl start nginx"
	if code, _, _ := hookRun(t, "pre", hookJSON("Bash", blocked, "req-d"), SocketPath(a.cfg.StateDir)); code != 2 {
		t.Fatal(code)
	}
	b.expect("tool_call")

	for i, command := range []string{
		"touch /tmp/anything",           // never recorded
		"sudo -n systemctl start nginx", // only attached to a blocked call
		"rm -rf /",                      // deny tier
		"",                              // empty
	} {
		tell(t, c, map[string]any{"type": "undo", "toolCallId": 20 + i, "command": command})
		if m := b.expect("undo_result"); m["exitCode"] != float64(refusedExitCode) {
			t.Fatalf("%q: %v", command, m)
		}
	}
}

func TestUndoLedgerSurvivesRestart(t *testing.T) {
	dir := stateDir(t)
	l := &auditLog{path: filepath.Join(dir, "audit.jsonl")}
	if err := l.write(auditRecord{Event: "call", Decision: "approved", Undo: "systemctl start x"}); err != nil {
		t.Fatal(err)
	}
	l2 := &auditLog{path: l.path}
	if !l2.hasUndo("systemctl start x") || l2.hasUndo("systemctl start y") || l2.hasUndo("") {
		t.Fatal("ledger lookup wrong")
	}
	if info, _ := os.Stat(l.path); info.Mode().Perm() != 0o600 {
		t.Fatalf("audit log mode %o", info.Mode().Perm())
	}
}

// Every rule that skips the prompt tool has to be something the classifier
// also calls auto. Otherwise layer one would be wider than the policy.
func TestAllowedToolsAreAutoTier(t *testing.T) {
	for _, rule := range allowedTools {
		if rule == "Read" {
			continue
		}
		body, ok := strings.CutPrefix(rule, "Bash(")
		if !ok || !strings.HasSuffix(body, "*)") {
			t.Fatalf("unexpected rule %q", rule)
		}
		prefix := strings.TrimSuffix(body, "*)")
		command := prefix + "nginx"
		if strings.HasSuffix(prefix, "--query") {
			command = prefix + "-gpu=power.draw"
		} else if strings.HasSuffix(prefix, "-q") {
			command = prefix
		}
		if tier, why := classify.Command(command); tier != classify.Auto {
			t.Errorf("%s: %q is %s (%s)", rule, command, tier, why)
		}
	}
}

// The prompt teaches these exact spellings, so they have to pass.
func TestPromptExamplesPassTheClassifier(t *testing.T) {
	found := 0
	for _, line := range strings.Split(promptTemplate, "\n") {
		if !strings.Contains(line, "# undo: ") || strings.Contains(line, "<") {
			continue
		}
		found++
		v := classify.Evaluate("Bash", input(strings.TrimSpace(line)))
		if v.Tier != classify.Approve || v.Blocked {
			t.Errorf("%q: %+v", line, v)
		}
	}
	if found != 2 {
		t.Fatalf("found %d examples", found)
	}
	read, _ := json.Marshal(map[string]string{"file_path": latestPath("/var/lib/greenserver/state")})
	if v := classify.Evaluate("Read", read); v.Tier != classify.Auto {
		t.Fatalf("Claude must be able to remeasure: %+v", v)
	}
}

func TestChildEnv(t *testing.T) {
	env := []string{"PATH=/bin", "ANTHROPIC_API_KEY=k", "ANTHROPIC_AUTH_TOKEN=a", "GREENSERVER_TOKEN=t", "HOME=/h", "MCP_TOOL_TIMEOUT=1"}
	has := func(list []string, name string) bool {
		for _, kv := range list {
			if strings.HasPrefix(kv, name+"=") {
				return true
			}
		}
		return false
	}
	sub := childEnv(env, "subscription")
	if has(sub, "ANTHROPIC_API_KEY") || has(sub, "ANTHROPIC_AUTH_TOKEN") || has(sub, "GREENSERVER_TOKEN") || !has(sub, "HOME") {
		t.Fatalf("%v", sub)
	}
	key := childEnv(env, "api_key")
	if !has(key, "ANTHROPIC_API_KEY") || has(key, "GREENSERVER_TOKEN") {
		t.Fatalf("%v", key)
	}
}

func TestParseStream(t *testing.T) {
	final := func(result string) string {
		line, _ := json.Marshal(map[string]any{"type": "result", "subtype": "success", "is_error": false, "result": result})
		return `{"type":"system","subtype":"init"}` + "\nnot json at all\n" + `{"type":"assistant"}` + "\n" + string(line) + "\n"
	}
	good := `{"summary":"요약","recommendations":[{"type":"idle","detail":"끄기","estSavingKrw":1200}]}`
	for name, text := range map[string]string{
		"bare":    good,
		"fenced":  "```json\n" + good + "\n```",
		"wrapped": "결과입니다.\n" + good + "\n끝.",
	} {
		res, err := parseStream(strings.NewReader(final(text)))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if res.Summary != "요약" || len(res.Recommendations) != 1 || res.Recommendations[0].EstSavingKrw != 1200 {
			t.Fatalf("%s: %+v", name, res)
		}
	}
	for name, stream := range map[string]string{
		"empty":      "",
		"no result":  `{"type":"assistant"}`,
		"not json":   final("그냥 문장입니다"),
		"no summary": final(`{"recommendations":[]}`),
		"max turns":  `{"type":"result","subtype":"error_max_turns","is_error":true}`,
		"is_error":   `{"type":"result","subtype":"success","is_error":true,"result":"{\"summary\":\"x\"}"}`,
	} {
		if _, err := parseStream(strings.NewReader(stream)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

const streamOK = `{"type":"system","subtype":"init"}
{"type":"result","subtype":"success","is_error":false,"result":"{\"summary\":\"유휴 서비스 1개\",\"recommendations\":[{\"type\":\"idle\",\"detail\":\"끄기\",\"estSavingKrw\":900}]}"}
`

// fakeClaude puts a script named claude first on PATH. The real one must stay
// out of reach: running it would spend the owner's subscription.
func fakeClaude(t *testing.T, stream string, exit int) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "stream"), []byte(stream), 0o600); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf("#!/bin/sh\ncd %q\nfor a in \"$@\"; do printf '%%s\\n' \"$a\"; done > args\nenv > env\ncat > prompt\ncat stream\nexit %d\n", dir, exit)
	if err := os.WriteFile(filepath.Join(dir, "claude"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":/usr/bin:/bin")
	got, err := exec.LookPath("claude")
	if err != nil || got != filepath.Join(dir, "claude") {
		t.Fatalf("fake claude not first on PATH: %s %v", got, err)
	}
	return dir
}

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func consult(t *testing.T, stream string, exit int, authMode string) (*fakeBackend, map[string]any, string) {
	t.Helper()
	dir := fakeClaude(t, stream, exit)
	b := newBackend(t)
	start(t, newAgent(t, b.url))
	c := b.conn()
	b.expect("hello")
	tell(t, c, map[string]any{"type": "consultation_start", "consultationId": 42, "authMode": authMode, "model": "claude-sonnet-5-5", "maxTurns": 15})
	if m := b.expect("consultation_status"); m["status"] != "running" || m["consultationId"] != float64(42) {
		t.Fatalf("%v", m)
	}
	return b, b.expect("consultation_status"), dir
}

func TestConsultationEndToEnd(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "must-not-leak")
	t.Setenv("GREENSERVER_TOKEN", "must-not-leak")
	_, m, dir := consult(t, streamOK, 0, "subscription")
	if m["status"] != "done" || m["summary"] != "유휴 서비스 1개" {
		t.Fatalf("%v", m)
	}
	recs := m["recommendations"].([]any)
	if len(recs) != 1 || recs[0].(map[string]any)["estSavingKrw"] != float64(900) {
		t.Fatalf("%v", recs)
	}

	args := strings.Split(strings.TrimSpace(read(t, filepath.Join(dir, "args"))), "\n")
	flag := func(name string) string {
		for i, a := range args {
			if a == name {
				if i+1 < len(args) {
					return args[i+1]
				}
				return ""
			}
		}
		t.Fatalf("missing %s in %v", name, args)
		return ""
	}
	flag("-p")
	flag("--verbose")
	flag("--strict-mcp-config")
	if flag("--output-format") != "stream-json" || flag("--max-turns") != "15" || flag("--permission-prompt-tool") != "mcp__greenserver__approve" {
		t.Fatalf("%v", args)
	}
	if !strings.Contains(flag("--allowedTools"), "Bash(systemctl status *)") || !strings.Contains(flag("--disallowedTools"), "Bash(rm -rf *)") {
		t.Fatalf("%v", args)
	}
	var settings struct {
		Hooks map[string][]struct {
			Matcher string `json:"matcher"`
			Hooks   []struct{ Type, Command string }
		} `json:"hooks"`
	}
	if err := json.Unmarshal([]byte(flag("--settings")), &settings); err != nil {
		t.Fatal(err)
	}
	for event, kind := range map[string]string{"PreToolUse": "hook pre", "PostToolUse": "hook post", "PostToolUseFailure": "hook post"} {
		if got := settings.Hooks[event]; len(got) != 1 || got[0].Matcher != "*" || !strings.Contains(got[0].Hooks[0].Command, kind) {
			t.Fatalf("%s: %+v", event, got)
		}
	}
	var mcp struct {
		MCPServers map[string]struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal([]byte(flag("--mcp-config")), &mcp); err != nil {
		t.Fatal(err)
	}
	if got := mcp.MCPServers["greenserver"]; len(got.Args) == 0 || got.Args[0] != "mcp-approve" {
		t.Fatalf("%+v", mcp)
	}

	env := read(t, filepath.Join(dir, "env"))
	if strings.Contains(env, "must-not-leak") {
		t.Fatalf("secret reached claude:\n%s", env)
	}

	prompt := read(t, filepath.Join(dir, "prompt"))
	for _, want := range []string{"측정한 데이터만", "백업", "되돌리는 명령어", "한 번에 하나씩", "재측정", "가용성", "접속자가 있으면 중지", "JSON", "# undo:", "latest-metrics.json"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("prompt lacks %q", want)
		}
	}
}

func TestAPIKeyModeKeepsTheKeyForClaude(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "owner-key")
	_, m, dir := consult(t, streamOK, 0, "api_key")
	if m["status"] != "done" || !strings.Contains(read(t, filepath.Join(dir, "env")), "ANTHROPIC_API_KEY=owner-key") {
		t.Fatalf("%v", m)
	}
}

func TestConsultationFailures(t *testing.T) {
	for name, c := range map[string]struct {
		stream string
		exit   int
	}{
		"bad exit":   {streamOK, 1},
		"no json":    {`{"type":"result","subtype":"success","is_error":false,"result":"모르겠습니다"}` + "\n", 0},
		"turn limit": {`{"type":"result","subtype":"error_max_turns","is_error":true}` + "\n", 1},
		"silent":     {"", 0},
	} {
		t.Run(name, func(t *testing.T) {
			if _, m, _ := consult(t, c.stream, c.exit, "subscription"); m["status"] != "failed" || m["summary"] == "" {
				t.Fatalf("%v", m)
			}
		})
	}
}

func TestConsultationValidation(t *testing.T) {
	fakeClaude(t, streamOK, 0)
	b := newBackend(t)
	start(t, newAgent(t, b.url))
	c := b.conn()
	b.expect("hello")
	for _, bad := range []map[string]any{
		{"type": "consultation_start", "consultationId": 1, "authMode": "stolen", "model": "claude-sonnet-5-5", "maxTurns": 5},
		{"type": "consultation_start", "consultationId": 2, "authMode": "api_key", "model": "claude-sonnet-5-5", "maxTurns": 0},
	} {
		tell(t, c, bad)
		if m := b.expect("consultation_status"); m["status"] != "failed" {
			t.Fatalf("%v", m)
		}
	}
}

func TestOnlyOneConsultationAtATime(t *testing.T) {
	a, b, c := connected(t) // already has consultation 7 open
	tell(t, c, map[string]any{"type": "consultation_start", "consultationId": 8, "authMode": "api_key", "model": "claude-sonnet-5-5", "maxTurns": 5})
	if m := b.expect("consultation_status"); m["status"] != "failed" || m["consultationId"] != float64(8) {
		t.Fatalf("%v", m)
	}
	if a.current().id != 7 {
		t.Fatal("running consultation was replaced")
	}
}

func TestParseStreamLevel(t *testing.T) {
	line := func(level string) string {
		final, _ := json.Marshal(map[string]any{"level": level, "summary": "요약", "feedback": []string{"a"}, "fixes": []string{"b"}})
		ev, _ := json.Marshal(map[string]any{"type": "result", "subtype": "success", "result": string(final)})
		return string(ev) + "\n"
	}
	res, err := parseStream(strings.NewReader(line("critical")))
	if err != nil || res.Level != "critical" || res.Feedback[0] != "a" || res.Fixes[0] != "b" {
		t.Fatalf("%+v %v", res, err)
	}
	if res, err = parseStream(strings.NewReader(line("panic"))); err != nil || res.Level != "" {
		t.Fatalf("unknown level must be dropped: %+v %v", res, err)
	}
}
