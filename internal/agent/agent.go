// Package agent is the long-running side of greenserver: the outbound
// WebSocket, the local socket used by hooks and the MCP tool, and the Claude
// Code runner.
package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/green-server/server_app/internal/classify"
	"github.com/green-server/server_app/internal/metrics"
	"github.com/green-server/server_app/internal/priv"
)

const (
	refusedExitCode = 126 // undo_result for an undo this agent refused to run
	queueLimit      = 1000
	writeTimeout    = 10 * time.Second
	undoTimeout     = 2 * time.Minute
)

type Config struct {
	Server   string
	Token    string
	StateDir string
	Profile  metrics.Profile
	Version  string
}

func SocketPath(stateDir string) string { return filepath.Join(stateDir, "agent.sock") }

type consultation struct {
	id       int64
	ctx      context.Context
	readOnly bool
}

type Agent struct {
	cfg     Config
	url     string
	sampler *metrics.Sampler
	audit   *auditLog

	metricsEvery time.Duration
	backoffBase  time.Duration
	backoffMax   time.Duration
	runUndo      func(ctx context.Context, command string) int

	mu     sync.Mutex // also serializes WebSocket writes
	conn   *websocket.Conn
	queue  [][]byte // reliable messages waiting for a link
	active *consultation

	approvalWait time.Duration
	down         chan struct{} // closed when the current link drops
	pending      map[string]pendingCall
	grants       map[string]priv.Grant // command -> signed permission, handed out once
}

// pendingCall waits for the owner to allow a privileged command in the browser.
type pendingCall struct {
	decision chan string
	command  string
}

func New(cfg Config) (*Agent, error) {
	u, err := endpoint(cfg.Server)
	if err != nil {
		return nil, err
	}
	if cfg.Token == "" {
		return nil, errors.New("missing agent token")
	}
	if err := cfg.Profile.Validate(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	return &Agent{
		cfg:          cfg,
		url:          u,
		audit:        &auditLog{path: filepath.Join(cfg.StateDir, "audit.jsonl")},
		metricsEvery: 10 * time.Second,
		backoffBase:  time.Second,
		backoffMax:   time.Minute,
		runUndo: func(ctx context.Context, command string) int {
			return shellUndo(ctx, command, SocketPath(cfg.StateDir))
		},
		approvalWait: 10 * time.Minute,
		pending:      map[string]pendingCall{},
		grants:       map[string]priv.Grant{},
	}, nil
}

// endpoint validates the server URL. Plain ws:// would send the token in the
// clear, so it is only accepted on loopback, for local development.
func endpoint(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid server URL %q", raw)
	}
	switch u.Scheme {
	case "wss":
	case "ws":
		host := u.Hostname()
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return "", fmt.Errorf("refusing unencrypted ws:// to %s, use wss://", host)
		}
	default:
		return "", fmt.Errorf("server URL must be wss://, got %q", u.Scheme)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/ws/agent"
	}
	return u.String(), nil
}

// Run blocks until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	ln, err := a.listen()
	if err != nil {
		return err
	}
	defer ln.Close()
	go a.serveIPC(ctx, ln)
	if a.sampler == nil {
		a.sampler = metrics.New(a.cfg.Profile)
	}
	go a.metricsLoop(ctx)

	backoff := a.backoffBase
	for ctx.Err() == nil {
		started := time.Now()
		err := a.session(ctx)
		if ctx.Err() != nil {
			break
		}
		if time.Since(started) > 30*time.Second {
			backoff = a.backoffBase
		}
		log.Printf("backend link down (%v), retrying in %s", err, backoff)
		select {
		case <-time.After(backoff + time.Duration(rand.Int64N(int64(backoff)/4+1))):
		case <-ctx.Done():
		}
		backoff = min(backoff*2, a.backoffMax)
	}
	return nil
}

func (a *Agent) session(ctx context.Context) error {
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(dialCtx, a.url, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": {"Bearer " + a.cfg.Token}},
	})
	if err != nil {
		return err
	}
	defer conn.CloseNow()
	conn.SetReadLimit(1 << 20)
	if err := a.attach(ctx, conn); err != nil {
		return err
	}
	defer a.detach()

	// A silently dead link would otherwise leave an approval waiting on a
	// network that is gone until TCP gives up.
	stop := make(chan struct{})
	defer close(stop)
	go a.keepalive(ctx, conn, stop)

	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return err
		}
		var m incoming
		if err := json.Unmarshal(data, &m); err != nil {
			log.Printf("ignoring malformed backend message: %v", err)
			continue
		}
		a.handle(ctx, m)
	}
}

func (a *Agent) keepalive(ctx context.Context, conn *websocket.Conn, stop <-chan struct{}) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			pingCtx, cancel := context.WithTimeout(ctx, writeTimeout)
			err := conn.Ping(pingCtx)
			cancel()
			if err != nil {
				conn.CloseNow()
				return
			}
		}
	}
}

// attach sends hello, then everything queued while offline, then opens the
// link for other senders.
func (a *Agent) attach(ctx context.Context, conn *websocket.Conn) error {
	host, _ := os.Hostname()
	hello, err := json.Marshal(helloMsg{"hello", a.cfg.Version, host, runtime.GOOS + "/" + runtime.GOARCH})
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := write(ctx, conn, hello); err != nil {
		return err
	}
	for len(a.queue) > 0 {
		if err := write(ctx, conn, a.queue[0]); err != nil {
			return err
		}
		a.queue = a.queue[1:]
	}
	a.conn, a.down = conn, make(chan struct{})
	return nil
}

func (a *Agent) detach() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.conn = nil
	close(a.down) // every permission waiting on this link is now denied
}

func write(ctx context.Context, conn *websocket.Conn, data []byte) error {
	ctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	return conn.Write(ctx, websocket.MessageText, data)
}

// send writes now or not at all. Used for metrics, which go stale anyway.
func (a *Agent) send(v any) bool {
	data, err := json.Marshal(v)
	if err != nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.writeLocked(data)
}

func (a *Agent) writeLocked(data []byte) bool {
	if a.conn == nil {
		return false
	}
	if err := write(context.Background(), a.conn, data); err != nil {
		a.conn.CloseNow()
		return false
	}
	return true
}

// sendReliable keeps the record of what happened across a link drop.
func (a *Agent) sendReliable(v any) {
	data, err := json.Marshal(v)
	if err != nil {
		log.Printf("cannot encode message: %v", err)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.writeLocked(data) {
		return
	}
	if len(a.queue) >= queueLimit {
		a.queue = a.queue[1:]
	}
	a.queue = append(a.queue, data)
}

func (a *Agent) handle(ctx context.Context, m incoming) {
	switch m.Type {
	case "consultation_start":
		a.startConsultation(ctx, m)
	case "decision":
		a.mu.Lock()
		p, ok := a.pending[m.RequestID]
		delete(a.pending, m.RequestID)
		if ok && m.Decision == "approved" && m.Grant != nil {
			a.grants[p.command] = *m.Grant
		}
		a.mu.Unlock()
		if ok {
			p.decision <- m.Decision
		}
	case "undo":
		if m.Grant != nil {
			a.mu.Lock()
			a.grants[m.Command] = *m.Grant
			a.mu.Unlock()
		}
		go a.handleUndo(ctx, m.ToolCallID, m.Command)
	}
}

func (a *Agent) metricsLoop(ctx context.Context) {
	t := time.NewTicker(a.metricsEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s, err := a.sampler.Sample()
		if err != nil {
			log.Printf("metrics: %v", err)
			continue
		}
		m := metricsMsg{"metrics", time.Now().UTC().Format(time.RFC3339), s.CPUPct, s.MemPct, s.Watts, s.IsEstimated, s.Processes}
		a.send(m)
		a.writeLatest(m)
	}
}

// writeLatest gives Claude something to remeasure with: the agent's own
// reading, which it can open with the Read tool between changes.
func (a *Agent) writeLatest(m metricsMsg) {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return
	}
	path := latestPath(a.cfg.StateDir)
	if err := os.WriteFile(path+".tmp", data, 0o600); err == nil {
		os.Rename(path+".tmp", path)
	}
}

func latestPath(stateDir string) string { return filepath.Join(stateDir, "latest-metrics.json") }

// handleUndo runs an undo only if it is byte for byte one this agent recorded
// on an approved action. The backend is a trust boundary: without this check
// a compromised backend could run any command on every connected server.
func (a *Agent) handleUndo(ctx context.Context, id int64, command string) {
	code := refusedExitCode
	tier, _ := classify.Command(command)
	switch {
	case tier == classify.Deny:
		log.Printf("undo %d refused: deny tier", id)
	case !a.audit.hasUndo(command):
		log.Printf("undo %d refused: not an undo this agent recorded", id)
	default:
		code = a.runUndo(ctx, command)
	}
	if err := a.audit.write(auditRecord{Event: "undo", Command: command, ExitCode: &code}); err != nil {
		log.Printf("audit: %v", err)
	}
	a.sendReliable(undoResultMsg{"undo_result", id, code})
}

func shellUndo(ctx context.Context, command, socket string) int {
	ctx, cancel := context.WithTimeout(ctx, undoTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", command)
	cmd.Env = append(childEnv(os.Environ(), "subscription"), socketEnv+"="+socket)
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &exit):
		return exit.ExitCode()
	}
	return refusedExitCode
}

// listen opens the local socket. The directory is 0700 and the socket 0600,
// so only the greenserver account can connect. That includes Claude's Bash,
// which is why the protocol carries no way to say "approved": it can only ask.
func (a *Agent) listen() (net.Listener, error) {
	path := SocketPath(a.cfg.StateDir)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

func (a *Agent) serveIPC(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				log.Printf("local socket: %v", err)
			}
			return
		}
		go func() {
			defer conn.Close()
			var req ipcRequest
			if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&req); err != nil {
				return
			}
			json.NewEncoder(conn).Encode(a.dispatch(req))
		}()
	}
}

func (a *Agent) current() *consultation {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.active
}

// dispatch re-evaluates every request itself: the caller's own classification
// is never trusted, and nothing is allowed outside a running consultation.
func (a *Agent) dispatch(req ipcRequest) ipcResponse {
	if req.Kind == kindGrant {
		return a.takeGrant(req.Command)
	}
	c := a.current()
	if c == nil {
		return ipcResponse{Message: "no consultation is running"}
	}
	if req.Kind == kindPost {
		a.recordResult(c, req)
		return ipcResponse{Allow: true}
	}
	v := classify.Evaluate(req.Tool, req.Input)
	// A plan must not touch the server, whatever the model decides to try.
	if c.readOnly && !v.Blocked && v.Tier != classify.Auto {
		v.Blocked, v.Reason = true, "계획 단계에서는 읽기 명령만 실행할 수 있습니다"
	}
	switch req.Kind {
	case kindPre:
		return a.preCheck(c, req, v)
	case kindApprove:
		return a.approve(c, req, v)
	}
	return ipcResponse{Message: "unknown request"}
}

func (a *Agent) preCheck(c *consultation, req ipcRequest, v classify.Verdict) ipcResponse {
	switch {
	case v.Blocked:
		a.reportBlocked(c, req.ToolUseID, v)
		return ipcResponse{Message: v.Reason}
	case v.Tier == classify.Auto:
		a.sendReliable(toolCallMsg{"tool_call", c.id, req.ToolUseID, v.Command, v.Tier, "auto", nil})
		a.logCall(c, req.ToolUseID, v, "auto")
	case strings.HasPrefix(v.Command, priv.Prefix):
		return a.requestPermission(c, req, v)
	default:
		// Runs without a human: every consultation is auto. Recorded first, because
		// the audit log is the undo ledger and an action must not run unrecorded.
		if err := a.logCall(c, req.ToolUseID, v, "auto"); err != nil {
			return ipcResponse{Message: "undo could not be recorded"}
		}
		a.sendReliable(toolCallMsg{"tool_call", c.id, req.ToolUseID, v.Command, v.Tier, "auto", undoPtr(v)})
	}
	return ipcResponse{Allow: true}
}

// requestPermission holds a privileged command until the owner decides in the
// browser. Everything else in a consultation is auto; this is the one human gate,
// and the helper enforces it, because only an allowed call comes back signed.
func (a *Agent) requestPermission(c *consultation, req ipcRequest, v classify.Verdict) ipcResponse {
	if _, err := priv.Parse(v.Command); err != nil {
		v.Reason = err.Error()
		a.reportBlocked(c, req.ToolUseID, v)
		return ipcResponse{Message: v.Reason}
	}
	id := req.ToolUseID
	decision := a.waitForDecision(c, id, v)
	if err := a.logCall(c, id, v, decision); err != nil && decision == "approved" {
		decision = "undo could not be recorded"
	}
	if decision != "approved" {
		a.takeGrant(v.Command)
		a.sendReliable(toolResultMsg{"tool_result", id, nil})
		return ipcResponse{Message: "denied: " + decision}
	}
	return ipcResponse{Allow: true}
}

// takeGrant hands a permission to `greenserver priv` once.
func (a *Agent) takeGrant(command string) ipcResponse {
	a.mu.Lock()
	defer a.mu.Unlock()
	g, ok := a.grants[command]
	if !ok {
		return ipcResponse{Message: "no permission for this command"}
	}
	delete(a.grants, command)
	return ipcResponse{Allow: true, Grant: &g}
}

// waitForDecision returns "approved" or why it was not. Only an explicit
// approved over a live link counts: silence, a dropped link or anything
// malformed is a denial.
func (a *Agent) waitForDecision(c *consultation, id string, v classify.Verdict) string {
	data, err := json.Marshal(toolCallMsg{"tool_call", c.id, id, v.Command, v.Tier, "pending", undoPtr(v)})
	if err != nil {
		return "unencodable request"
	}
	ch := make(chan string, 1)
	a.mu.Lock()
	if _, dup := a.pending[id]; dup {
		a.mu.Unlock()
		return "duplicate request"
	}
	if !a.writeLocked(data) {
		a.mu.Unlock()
		return "backend link is down"
	}
	a.pending[id] = pendingCall{ch, v.Command}
	down := a.down
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		delete(a.pending, id)
		a.mu.Unlock()
	}()

	timer := time.NewTimer(a.approvalWait)
	defer timer.Stop()
	select {
	case d := <-ch:
		if d == "approved" {
			return d
		}
		return "denied by the owner"
	case <-timer.C:
		return "approval timed out"
	case <-down:
		return "backend link dropped"
	case <-c.ctx.Done():
		return "consultation ended"
	}
}

// approve answers the prompt tool. The pre hook already recorded the call, so
// the only refusal left here is the classifier's own.
func (a *Agent) approve(c *consultation, req ipcRequest, v classify.Verdict) ipcResponse {
	if v.Blocked {
		id := req.ToolUseID
		if id == "" {
			id = fmt.Sprintf("gs-%d-%d", time.Now().UnixNano(), rand.Int64())
		}
		a.reportBlocked(c, id, v)
		return ipcResponse{Message: v.Reason}
	}
	return ipcResponse{Allow: true}
}

func (a *Agent) reportBlocked(c *consultation, id string, v classify.Verdict) {
	a.sendReliable(toolCallMsg{"tool_call", c.id, id, v.Command, v.Tier, "blocked", undoPtr(v)})
	a.logCall(c, id, v, "blocked")
}

func undoPtr(v classify.Verdict) *string {
	if v.Undo == "" {
		return nil
	}
	return &v.Undo
}

func (a *Agent) recordResult(c *consultation, req ipcRequest) {
	a.sendReliable(toolResultMsg{"tool_result", req.ToolUseID, req.ExitCode})
	v := classify.Evaluate(req.Tool, req.Input)
	err := a.audit.write(auditRecord{Event: "result", ConsultationID: c.id, RequestID: req.ToolUseID, Tool: req.Tool, Command: v.Command, ExitCode: req.ExitCode})
	if err != nil {
		log.Printf("audit: %v", err)
	}
}

func (a *Agent) logCall(c *consultation, id string, v classify.Verdict, decision string) error {
	err := a.audit.write(auditRecord{Event: "call", ConsultationID: c.id, RequestID: id, Command: v.Command, Tier: v.Tier, Decision: decision, Undo: v.Undo})
	if err != nil {
		log.Printf("audit: %v", err)
	}
	return err
}

// auditRecord is one line of the local audit log. Lines carrying an Undo are
// also the ledger that an undo request is checked against, so
// undo works across restarts.
type auditRecord struct {
	TS             string        `json:"ts"`
	Event          string        `json:"event"`
	ConsultationID int64         `json:"consultationId,omitempty"`
	RequestID      string        `json:"requestId,omitempty"`
	Tool           string        `json:"tool,omitempty"`
	Command        string        `json:"command"`
	Tier           classify.Tier `json:"tier,omitempty"`
	Decision       string        `json:"decision,omitempty"`
	Undo           string        `json:"undo,omitempty"`
	ExitCode       *int          `json:"exitCode,omitempty"`
}

type auditLog struct {
	mu   sync.Mutex
	path string
}

func (l *auditLog) write(r auditRecord) error {
	r.TS = time.Now().UTC().Format(time.RFC3339)
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(data, '\n'))
	return err
}

func (l *auditLog) hasUndo(command string) bool {
	if command == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.Open(l.path)
	if err != nil {
		return false
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64*1024), 1<<20)
	for s.Scan() {
		var r auditRecord
		if json.Unmarshal(s.Bytes(), &r) == nil && (r.Decision == "auto" || r.Decision == "approved") && r.Undo == command {
			return true
		}
	}
	return false
}
