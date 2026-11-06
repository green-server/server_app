package agent

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/green-server/server_app/internal/classify"
)

// Everything here runs in short-lived processes started by Claude Code.

// call sends one request to the running agent. It must outlast the approval
// window, and failing it counts as a refusal on the caller's side.
func call(socket string, req ipcRequest) (ipcResponse, error) {
	var resp ipcResponse
	conn, err := net.DialTimeout("unix", socket, 5*time.Second)
	if err != nil {
		return resp, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(11 * time.Minute))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return resp, err
	}
	err = json.NewDecoder(bufio.NewReader(conn)).Decode(&resp)
	return resp, err
}

type hookInput struct {
	Event     string          `json:"hook_event_name"`
	Tool      string          `json:"tool_name"`
	Input     json.RawMessage `json:"tool_input"`
	ToolUseID string          `json:"tool_use_id"`
	Error     string          `json:"error"`
}

// Hook runs `greenserver hook pre|post` and returns the process exit code.
//
// Exit code 2 is the only code with which a PreToolUse hook blocks a call;
// claude treats any other failure as a warning and carries on. Every failure
// path of the pre hook therefore returns 2.
func Hook(kind string, stdin io.Reader, stdout, stderr io.Writer, socket string) int {
	var in hookInput
	if err := json.NewDecoder(stdin).Decode(&in); err != nil {
		fmt.Fprintf(stderr, "greenserver: unreadable hook input: %v\n", err)
		if kind == "pre" {
			return 2
		}
		return 1
	}
	if kind == "post" {
		return postHook(in, stderr, socket)
	}
	return preHook(in, stdout, stderr, socket)
}

func preHook(in hookInput, stdout, stderr io.Writer, socket string) int {
	if in.Tool == approveTool {
		return 0 // the prompt tool's own plumbing; it checks everything itself
	}
	// Decide locally first, so a broken agent cannot weaken the classifier.
	v := classify.Evaluate(in.Tool, in.Input)
	resp, err := call(socket, ipcRequest{Kind: kindPre, Tool: in.Tool, Input: in.Input, ToolUseID: in.ToolUseID})
	switch {
	case v.Blocked:
		fmt.Fprintln(stderr, "greenserver: blocked:", v.Reason)
		return 2
	case err != nil:
		fmt.Fprintln(stderr, "greenserver: blocked, agent unreachable:", err)
		return 2
	case !resp.Allow:
		fmt.Fprintln(stderr, "greenserver: blocked:", resp.Message)
		return 2
	}
	return 0
}

var exitCodeText = regexp.MustCompile(`(?i)exit code (\d+)`)

func postHook(in hookInput, stderr io.Writer, socket string) int {
	if in.Tool == approveTool {
		return 0
	}
	if _, err := call(socket, ipcRequest{Kind: kindPost, Tool: in.Tool, Input: in.Input, ToolUseID: in.ToolUseID, ExitCode: exitCode(in)}); err != nil {
		fmt.Fprintln(stderr, "greenserver: could not record result:", err)
		return 1
	}
	return 0
}

// exitCode: Claude Code reports success through PostToolUse with no code, and
// failure through PostToolUseFailure with the code inside an error string.
func exitCode(in hookInput) *int {
	code := 0
	if in.Event == "PostToolUseFailure" {
		m := exitCodeText.FindStringSubmatch(in.Error)
		if m == nil {
			return nil
		}
		code, _ = strconv.Atoi(m[1])
	}
	return &code
}

type rpcMessage struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

// ServeMCP is a minimal stdio MCP server exposing the permission prompt tool.
// Claude Code calls it with the tool name and input; it answers with a single
// text block holding {"behavior":"allow",...} or {"behavior":"deny",...}.
func ServeMCP(in io.Reader, out io.Writer, socket string) error {
	var mu sync.Mutex
	var wg sync.WaitGroup
	reply := func(id json.RawMessage, key string, value any) {
		data, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, key: value})
		mu.Lock()
		defer mu.Unlock()
		out.Write(append(data, '\n'))
	}
	s := bufio.NewScanner(in)
	s.Buffer(make([]byte, 64*1024), 8<<20)
	for s.Scan() {
		var m rpcMessage
		if json.Unmarshal(s.Bytes(), &m) != nil || len(m.ID) == 0 {
			continue // notifications need no answer
		}
		switch m.Method {
		case "initialize":
			var p struct {
				ProtocolVersion string `json:"protocolVersion"`
			}
			json.Unmarshal(m.Params, &p)
			reply(m.ID, "result", map[string]any{
				"protocolVersion": p.ProtocolVersion,
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]string{"name": serverName, "version": "1"},
			})
		case "ping":
			reply(m.ID, "result", map[string]any{})
		case "tools/list":
			reply(m.ID, "result", map[string]any{"tools": []map[string]any{approveToolSchema}})
		case "tools/call":
			wg.Add(1)
			go func() { // a call can wait 10 minutes; pings must still be answered
				defer wg.Done()
				text := approveCall(m.Params, socket)
				reply(m.ID, "result", map[string]any{"content": []map[string]string{{"type": "text", "text": text}}})
			}()
		default:
			reply(m.ID, "error", map[string]any{"code": -32601, "message": "method not found"})
		}
	}
	wg.Wait()
	return s.Err()
}

var approveToolSchema = map[string]any{
	"name":        "approve",
	"description": "Green Server permission prompt: asks the server owner on the web.",
	"inputSchema": map[string]any{
		"type": "object",
		"properties": map[string]any{
			"tool_name":   map[string]string{"type": "string"},
			"input":       map[string]string{"type": "object"},
			"tool_use_id": map[string]string{"type": "string"},
		},
		"required": []string{"tool_name", "input"},
	},
}

func approveCall(params json.RawMessage, socket string) string {
	deny := func(msg string) string {
		data, _ := json.Marshal(map[string]string{"behavior": "deny", "message": msg})
		return string(data)
	}
	var p struct {
		Name      string `json:"name"`
		Arguments struct {
			Tool      string          `json:"tool_name"`
			Input     json.RawMessage `json:"input"`
			ToolUseID string          `json:"tool_use_id"`
		} `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil || p.Name != "approve" {
		return deny("invalid approval request")
	}
	a := p.Arguments
	resp, err := call(socket, ipcRequest{Kind: kindApprove, Tool: a.Tool, Input: a.Input, ToolUseID: a.ToolUseID})
	if err != nil {
		return deny("agent unreachable, treated as denied")
	}
	if !resp.Allow {
		return deny(resp.Message)
	}
	data, err := json.Marshal(map[string]any{"behavior": "allow", "updatedInput": a.Input})
	if err != nil {
		return deny("cannot encode approval")
	}
	return string(data)
}
