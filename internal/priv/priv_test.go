package priv

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseAllowsOnlyExactShapes(t *testing.T) {
	for _, c := range []string{
		"docker restart minecraft-server", "docker stop minecraft-server", "docker start web_1",
		"systemctl stop nginx", "systemctl restart nginx.service",
		"cpupower frequency-set -g powersave", "powerprofilesctl set power-saver",
	} {
		if _, err := Parse(Prefix + c); err != nil {
			t.Errorf("%q: %v", c, err)
		}
	}
	for _, c := range []string{
		"docker run -v /:/host alpine sh", "docker exec minecraft-server sh", "docker rm -f x", "docker stop a b",
		"docker stop --time=0 x", "docker stop -t 0 x", "docker stop x;id", "docker stop $(id)", "docker stop `id`",
		"docker stop x|sh", "docker stop ../x", "systemctl disable nginx", "systemctl stop nginx ssh",
		"systemctl edit nginx", "bash -c id", "sh", "rm -rf /", "cpupower frequency-set -g evil",
		"powerprofilesctl set evil", "", "docker", "docker  stop x", " docker stop x", "docker stop x ",
		"docker stop x\nid",
	} {
		if argv, err := Parse(Prefix + c); err == nil {
			t.Errorf("%q must be refused, got %v", c, argv)
		}
	}
	if _, err := Parse("docker stop x"); err == nil {
		t.Error("no prefix")
	}
	if _, err := Parse("sudo " + Prefix + "docker stop x"); err == nil {
		t.Error("wrapped")
	}
}

func TestProtectedServicesCannotBeTouched(t *testing.T) {
	for _, n := range []string{
		"ssh", "sshd.service", "SSH", "openssh-server", "cloudflared", "tailscaled", "docker", "docker.service", "containerd",
		"fail2ban", "ufw", "greenserver", "greenserver-root", "sudo", "systemd-logind", "dokploy", "dokploy-traefik",
		"dokploy-postgres.1.abc", "green-back-q6kwcu", "green-mysql-o4ct69", "NetworkManager",
	} {
		for _, tool := range []string{"docker", "systemctl"} {
			if _, err := Parse(Prefix + tool + " stop " + n); err == nil {
				t.Errorf("%s %s must be protected", tool, n)
			}
		}
	}
}

// Only services by name: another unit type, a protected template's instance or
// a container ID would each slip past the protected list.
func TestParseRefusesProtectedListBypasses(t *testing.T) {
	for _, c := range []string{
		"systemctl start poweroff.target", "systemctl start reboot.target", "systemctl start halt.target",
		"systemctl start rescue.target", "systemctl start emergency.target", "systemctl start rescue",
		"systemctl stop ssh.socket", "systemctl stop sshd.socket", "systemctl stop docker.socket", "systemctl stop dbus.socket",
		"systemctl stop user@1000", "systemctl stop user@1000.service", "systemctl stop getty@tty1", "systemctl stop serial-getty@ttyS0.service",
		"systemctl stop ssh@x", "systemctl stop nginx.timer", "systemctl stop srv.mount", "systemctl stop x.path", "systemctl stop user.slice",
		"systemctl stop nginx.SOCKET", "systemctl stop nginx.service.service",
		"docker stop 3f2a9c1b7d4e", "docker stop 3f2a", "docker stop " + strings.Repeat("ab", 32),
	} {
		if argv, err := Parse(Prefix + c); err == nil {
			t.Errorf("%q must be refused, got %v", c, argv)
		}
	}
	for _, c := range []string{"systemctl stop php8.2-fpm", "systemctl restart nginx@site.service", "docker stop web-3f2a"} {
		if _, err := Parse(Prefix + c); err != nil {
			t.Errorf("%q: %v", c, err)
		}
	}
}

func signed(t *testing.T, key ed25519.PrivateKey, server, expires int64, nonce, command string) Grant {
	t.Helper()
	sig := ed25519.Sign(key, message(server, expires, nonce, command))
	return Grant{expires, nonce, base64.StdEncoding.EncodeToString(sig)}
}

const cmd = Prefix + "docker restart minecraft-server"

func helper(t *testing.T) (*Helper, ed25519.PrivateKey, *[][]string) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHelper(base64.StdEncoding.EncodeToString(pub), 7)
	if err != nil {
		t.Fatal(err)
	}
	ran := &[][]string{}
	h.Exec = func(_ context.Context, argv []string) (int, string) {
		*ran = append(*ran, argv)
		return 0, "ok"
	}
	h.Now = func() time.Time { return time.Unix(1000, 0) }
	return h, key, ran
}

func TestHelperRunsASignedCommandOnce(t *testing.T) {
	h, key, ran := helper(t)
	g := signed(t, key, 7, 2000, "n1", cmd)
	if r := h.Handle(context.Background(), Request{cmd, g}); r.Error != "" || r.ExitCode != 0 || r.Output != "ok" {
		t.Fatalf("%+v", r)
	}
	if len(*ran) != 1 || strings.Join((*ran)[0], " ") != "docker restart minecraft-server" {
		t.Fatalf("%v", *ran)
	}
	if r := h.Handle(context.Background(), Request{cmd, g}); r.ExitCode != 126 || !strings.Contains(r.Error, "used") {
		t.Fatalf("replay: %+v", r)
	}
	if len(*ran) != 1 {
		t.Fatal("replay ran")
	}
}

func TestHelperRefusesForgeries(t *testing.T) {
	h, key, ran := helper(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	stop := Prefix + "docker stop minecraft-server"
	for name, r := range map[string]Request{
		"no grant":             {cmd, Grant{}},
		"other key":            {cmd, signed(t, other, 7, 2000, "a", cmd)},
		"other server":         {cmd, signed(t, key, 8, 2000, "b", cmd)},
		"other command":        {stop, signed(t, key, 7, 2000, "c", cmd)},
		"expired":              {cmd, signed(t, key, 7, 1000, "d", cmd)},
		"changed expiry":       {cmd, func() Grant { g := signed(t, key, 7, 500, "e", cmd); g.Expires = 2000; return g }()},
		"changed nonce":        {cmd, func() Grant { g := signed(t, key, 7, 2000, "f", cmd); g.Nonce = "z"; return g }()},
		"bad base64":           {cmd, Grant{2000, "g", "%%%"}},
		"signed but protected": {Prefix + "docker stop dokploy", signed(t, key, 7, 2000, "h", Prefix+"docker stop dokploy")},
		"signed but off list":  {Prefix + "docker exec x sh", signed(t, key, 7, 2000, "i", Prefix+"docker exec x sh")},
	} {
		if resp := h.Handle(context.Background(), r); resp.ExitCode != 126 || resp.Error == "" {
			t.Errorf("%s: %+v", name, resp)
		}
	}
	if len(*ran) != 0 {
		t.Fatalf("ran %v", *ran)
	}
}

func TestNewHelperRejectsBadConfig(t *testing.T) {
	if _, err := NewHelper("short", 1); err == nil {
		t.Error("bad key")
	}
	if _, err := NewHelper(base64.StdEncoding.EncodeToString(make([]byte, 32)), 0); err == nil {
		t.Error("no server id")
	}
}

// Generated by back/src/grants.js: the two sides must agree on the wire format.
func TestVerifiesABackendSignature(t *testing.T) {
	raw, _ := base64.StdEncoding.DecodeString(backendPublicKey)
	if err := Verify(raw, 7, backendGrant, cmd, time.Unix(1000, 0)); err != nil {
		t.Fatal(err)
	}
}

func serve(t *testing.T, h *Helper) string {
	t.Helper()
	// Socket paths have a short OS limit, too short for t.TempDir on macOS.
	dir, err := os.MkdirTemp("/tmp", "gsp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "root.sock")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go h.Serve(ctx, socket, "")
	for range 100 {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	return socket
}

func TestServeRoundTrip(t *testing.T) {
	h, key, ran := helper(t)
	socket := serve(t, h)
	info, err := os.Stat(socket)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", info, err)
	}
	resp, err := Call(socket, Request{cmd, signed(t, key, 7, 2000, "wire", cmd)})
	if err != nil || resp.ExitCode != 0 || resp.Output != "ok" || len(*ran) != 1 {
		t.Fatalf("%+v %v", resp, err)
	}
	resp, err = Call(socket, Request{Command: cmd})
	if err != nil || resp.ExitCode != 126 || len(*ran) != 1 {
		t.Fatalf("%+v %v", resp, err)
	}
}

// A request over the size limit is dropped unread, even a validly signed one.
func TestServeRefusesOversizedRequest(t *testing.T) {
	h, key, ran := helper(t)
	socket := serve(t, h)
	grant, _ := json.Marshal(signed(t, key, 7, 2000, "big", cmd))
	payload := `{"command":"` + cmd + `",` + strings.Repeat(" ", maxRequest) + `"grant":` + string(grant) + "}\n"
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	go conn.Write([]byte(payload)) // fails once the helper hangs up
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err == nil {
		t.Fatalf("oversized request was answered: %+v", resp)
	}
	if len(*ran) != 0 {
		t.Fatalf("oversized request ran %v", *ran)
	}
}
