package priv

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

const (
	maxOutput   = 4096
	commandWait = 2 * time.Minute
)

// Request is what `greenserver priv` sends to the helper.
type Request struct {
	Command string `json:"command"`
	Grant   Grant  `json:"grant"`
}

// Response carries the exit code; a refusal has Error set and ran nothing.
type Response struct {
	ExitCode int    `json:"exitCode"`
	Output   string `json:"output"`
	Error    string `json:"error,omitempty"`
}

// Helper checks and runs privileged commands.
type Helper struct {
	Key      ed25519.PublicKey
	ServerID int64
	Exec     func(ctx context.Context, argv []string) (int, string) // replaced in tests
	Now      func() time.Time

	mu   sync.Mutex
	used map[string]int64 // nonce -> expiry, so a captured grant cannot run twice
}

// NewHelper parses the base64 public key.
func NewHelper(publicKey string, serverID int64) (*Helper, error) {
	raw, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("public key must be 32 base64 encoded bytes")
	}
	if serverID <= 0 {
		return nil, errors.New("server id is required")
	}
	return &Helper{Key: raw, ServerID: serverID, Exec: runArgv, Now: time.Now, used: map[string]int64{}}, nil
}

func (h *Helper) claim(g Grant) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.Now().Unix()
	for nonce, expires := range h.used {
		if expires < now {
			delete(h.used, nonce)
		}
	}
	if _, seen := h.used[g.Nonce]; seen {
		return false
	}
	h.used[g.Nonce] = g.Expires
	return true
}

// Handle refuses anything that is not on the list, signed and unused.
func (h *Helper) Handle(ctx context.Context, r Request) Response {
	argv, err := Parse(r.Command)
	if err == nil {
		err = Verify(h.Key, h.ServerID, r.Grant, r.Command, h.Now())
	}
	if err == nil && !h.claim(r.Grant) {
		err = errors.New("grant already used")
	}
	if err != nil {
		log.Printf("refused %q: %v", r.Command, err)
		return Response{ExitCode: 126, Error: err.Error()}
	}
	log.Printf("running %q", r.Command)
	code, output := h.Exec(ctx, argv)
	return Response{ExitCode: code, Output: output}
}

func runArgv(ctx context.Context, argv []string) (int, string) {
	ctx, cancel := context.WithTimeout(ctx, commandWait)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	out, err := cmd.CombinedOutput()
	if len(out) > maxOutput {
		out = out[:maxOutput]
	}
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0, string(out)
	case errors.As(err, &exit):
		return exit.ExitCode(), string(out)
	}
	return 127, err.Error()
}

// Serve listens on a socket only the given group can reach.
func (h *Helper) Serve(ctx context.Context, socket, group string) error {
	if err := os.MkdirAll(filepath.Dir(socket), 0o750); err != nil {
		return err
	}
	os.Remove(socket)
	ln, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer ln.Close()
	if err := restrict(socket, group); err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go h.serveConn(ctx, conn)
	}
}

func restrict(socket, group string) error {
	if group == "" {
		return os.Chmod(socket, 0o600)
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return err
	}
	if err := os.Chown(socket, 0, gid); err != nil {
		return err
	}
	if err := os.Chown(filepath.Dir(socket), 0, gid); err != nil {
		return err
	}
	return os.Chmod(socket, 0o660)
}

func (h *Helper) serveConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(commandWait + 10*time.Second))
	var r Request
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&r); err != nil {
		return
	}
	json.NewEncoder(conn).Encode(h.Handle(ctx, r))
}

// Call sends one request to the helper.
func Call(socket string, r Request) (Response, error) {
	conn, err := net.DialTimeout("unix", socket, 5*time.Second)
	if err != nil {
		return Response{}, fmt.Errorf("root helper is not available: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(commandWait + 15*time.Second))
	if err := json.NewEncoder(conn).Encode(r); err != nil {
		return Response{}, err
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return Response{}, err
	}
	return resp, nil
}
