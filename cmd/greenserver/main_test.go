package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// These run the built binary, to prove the wiring Claude Code depends on:
// exit codes, stdout and the token path. They only feed it JSON; nothing the
// JSON describes is ever executed.

func build(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "greenserver")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return bin
}

func TestHookExitCodes(t *testing.T) {
	bin := build(t)
	missing := filepath.Join(t.TempDir(), "none.sock")
	for name, c := range map[string]struct {
		args  []string
		stdin string
		want  int
	}{
		"deny blocks":      {[]string{"hook", "pre", "--socket", missing}, `{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}`, 2},
		"no agent blocks":  {[]string{"hook", "pre", "--socket", missing}, `{"tool_name":"Bash","tool_input":{"command":"ps aux"}}`, 2},
		"garbage blocks":   {[]string{"hook", "pre", "--socket", missing}, `nope`, 2},
		"bad kind blocks":  {[]string{"hook", "sideways"}, ``, 2},
		"bad flag blocks":  {[]string{"hook", "pre", "--wrong"}, ``, 2},
		"post never stops": {[]string{"hook", "post", "--socket", missing}, `{"tool_name":"Bash"}`, 1},
	} {
		cmd := exec.Command(bin, c.args...)
		cmd.Stdin = strings.NewReader(c.stdin)
		err := cmd.Run()
		code := 0
		if exit, ok := err.(*exec.ExitError); ok {
			code = exit.ExitCode()
		}
		if code != c.want {
			t.Errorf("%s: exit %d, want %d", name, code, c.want)
		}
	}
}

func TestMCPOverStdio(t *testing.T) {
	cmd := exec.Command(build(t), "mcp-approve", "--socket", "/nonexistent")
	cmd.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"name":"approve"`) {
		t.Fatalf("%q", out.String())
	}
}

func TestRunFromEnvToken(t *testing.T) {
	bin := build(t)
	auth, hello := make(chan string, 1), make(chan map[string]any, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		auth <- r.Header.Get("Authorization")
		_, data, err := c.Read(r.Context())
		if err != nil {
			return
		}
		var m map[string]any
		json.Unmarshal(data, &m)
		hello <- m
		c.Read(r.Context())
	}))
	defer srv.Close()

	state, err := os.MkdirTemp("/tmp", "gs")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(state)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "run", "--server", "ws"+strings.TrimPrefix(srv.URL, "http"), "--state-dir", state)
	cmd.Env = append(os.Environ(), "GREENSERVER_TOKEN=secret-token")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Wait()
	defer cmd.Process.Kill()

	select {
	case got := <-auth:
		if got != "Bearer secret-token" {
			t.Fatalf("%q", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("agent did not connect")
	}
	if m := <-hello; m["type"] != "hello" {
		t.Fatalf("%v", m)
	}
	if strings.Contains(strings.Join(cmd.Args, " "), "secret-token") {
		t.Fatal("token visible in the process arguments")
	}
}

func TestRunRejectsMissingToken(t *testing.T) {
	cmd := exec.Command(build(t), "run", "--server", "wss://example.com", "--state-dir", t.TempDir())
	cmd.Env = []string{"HOME=" + t.TempDir()}
	if err := cmd.Run(); err == nil {
		t.Fatal("started without a token")
	}
}
