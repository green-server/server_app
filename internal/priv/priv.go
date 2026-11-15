// Package priv runs the few root commands a consultation may use, and only
// with a grant the backend signed after the owner allowed it in the browser.
//
// Claude shares its account with the agent, so anything that account can read
// Claude can read too. The helper therefore runs as root and holds only a public
// key: without the signature nothing on this machine can forge permission.
package priv

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Prefix starts every privileged command Claude may ask for.
const Prefix = "greenserver priv "

// DefaultSocket is created by the root helper, for the greenserver group.
const DefaultSocket = "/run/greenserver-root/root.sock"

var name = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@-]*$`)

// protected can never be stopped, even with a valid grant: losing one of these
// locks the owner out or takes this system down with it.
var protected = regexp.MustCompile(`(?i)^(ssh|sshd|openssh.*|dropbear|cloudflared|tailscaled|docker|containerd|fail2ban|firewalld|ufw|nftables|iptables|ip6tables|greenserver.*|sudo|dbus|dbus-broker|polkit|networking|networkmanager|wpa_supplicant|systemd-.*|cron|dokploy.*|green-.*|getty|serial-getty|console-getty|container-getty|autovt|user|user-runtime-dir|rescue|emergency|poweroff|reboot|halt|kexec|debug-shell)$`)

// unitTypes are the suffixes systemctl reads as a unit type. Only services are
// on the list: a .target or .socket can power off the host or cut off ssh.
var unitTypes = map[string]bool{"service": true, "socket": true, "target": true, "device": true, "mount": true, "automount": true, "swap": true, "timer": true, "path": true, "slice": true, "scope": true}

// containerID matches what docker could resolve as a container ID or ID prefix,
// which would get past the name check below.
var containerID = regexp.MustCompile(`^[0-9a-f]+$`)

var (
	actions  = map[string]bool{"stop": true, "start": true, "restart": true}
	governor = map[string]bool{"powersave": true, "schedutil": true, "ondemand": true, "conservative": true, "performance": true}
	profile  = map[string]bool{"power-saver": true, "balanced": true, "performance": true}
)

// Parse turns a command into the argv the helper may run. The shapes are exact:
// there is no shell, and no docker run or exec, because each of those is root
// by another name.
func Parse(command string) ([]string, error) {
	rest, ok := strings.CutPrefix(command, Prefix)
	if !ok {
		return nil, errors.New("not a privileged command")
	}
	argv := strings.Fields(rest)
	if strings.Join(argv, " ") != rest {
		return nil, errors.New("unexpected spacing")
	}
	switch {
	case len(argv) == 3 && (argv[0] == "docker" || argv[0] == "systemctl") && actions[argv[1]]:
		if err := checkTarget(argv[0], argv[2]); err != nil {
			return nil, err
		}
		return argv, nil
	case len(argv) == 4 && argv[0] == "cpupower" && argv[1] == "frequency-set" && argv[2] == "-g" && governor[argv[3]]:
		return argv, nil
	case len(argv) == 3 && argv[0] == "powerprofilesctl" && argv[1] == "set" && profile[argv[2]]:
		return argv, nil
	}
	return nil, errors.New("this command is not on the privileged list")
}

func checkTarget(tool, target string) error {
	if !name.MatchString(target) {
		return fmt.Errorf("bad name %q", target)
	}
	base := strings.TrimSuffix(target, ".service")
	switch tool {
	case "docker":
		if containerID.MatchString(target) {
			return fmt.Errorf("%s looks like a container ID, use the container name", target)
		}
	case "systemctl":
		if i := strings.LastIndexByte(base, '.'); i >= 0 && unitTypes[strings.ToLower(base[i+1:])] {
			return fmt.Errorf("%s is not a service", target)
		}
		base, _, _ = strings.Cut(base, "@") // getty@tty1 is an instance of getty
	}
	if protected.MatchString(base) {
		return fmt.Errorf("%s is protected", target)
	}
	return nil
}

// Grant is the backend's signed permission for one exact command.
type Grant struct {
	Expires   int64  `json:"expires"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

// message must match grants.js in the backend byte for byte.
func message(serverID, expires int64, nonce, command string) []byte {
	return fmt.Appendf(nil, "green-server-grant-v1\n%d\n%d\n%s\n%s", serverID, expires, nonce, command)
}

// Verify checks that the backend signed this command for this server.
func Verify(key ed25519.PublicKey, serverID int64, g Grant, command string, now time.Time) error {
	if g.Nonce == "" {
		return errors.New("grant has no nonce")
	}
	if now.Unix() >= g.Expires {
		return errors.New("grant expired")
	}
	sig, err := base64.StdEncoding.DecodeString(g.Signature)
	if err != nil {
		return errors.New("bad signature encoding")
	}
	if !ed25519.Verify(key, message(serverID, g.Expires, g.Nonce, command), sig) {
		return errors.New("bad signature")
	}
	return nil
}
