package classify

import (
	"regexp"
	"strings"
)

func set(words string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(words) {
		m[w] = true
	}
	return m
}

// autoPlain is safe with any arguments. Commands with a mutating flag or verb
// are not here; they have a rule in walker.decide.
var autoPlain = set(`
	cat head tail wc ls stat file du df free uptime nproc lscpu lsblk lsmem lspci lsusb lsmod
	lsof pgrep pidof pstree vmstat iostat mpstat netstat sensors findmnt uname whoami id groups
	who w last pwd cd basename dirname realpath readlink which echo printf true false : test [ [[
	sleep wait cut tr column paste fold nl tac rev cmp diff comm md5sum sha1sum sha256sum strings
	od hexdump
`)

// metadataOnly commands reveal names and sizes, not contents, so a wildcard
// that might match a secret is harmless. A literal secret path still denies.
var metadataOnly = set(`ls du df stat wc file find`)

var shellKeywords = set(`if then elif else fi while until do done for in esac select { } !`)

var shells = set(`sh bash dash zsh ksh ash fish csh tcsh rbash`)

var interpreter = regexp.MustCompile(`^(python[0-9.]*|pypy[0-9.]*|perl[0-9.]*|ruby[0-9.]*|node|nodejs|php[0-9.]*|lua[0-9.]*|tclsh|deno|bun)$`)

var downloaders = set(`curl wget fetch aria2c`)

var denied = set(`
	dd shred wipefs fdisk sfdisk gdisk cfdisk parted blkdiscard lvremove vgremove pvremove mdadm
	cryptsetup zpool

	eval exec source . alias unalias trap

	ssh scp sftp sshd ssh-keygen ssh-copy-id ssh-add ssh-keyscan
	ufw nft firewall-cmd ipset ebtables arptables pfctl

	shutdown reboot poweroff halt init telinit kexec

	su doas pkexec runuser sudoedit visudo passwd chpasswd useradd usermod userdel adduser deluser
	groupadd groupmod groupdel gpasswd setcap chattr
	nsenter unshare chroot capsh systemd-run at batch insmod rmmod modprobe

	nc ncat netcat socat telnet ftp

	env printenv set declare typeset export compgen
	gdb gcore strace ltrace ptrace
`)

// wrappers launch the command that follows them. An unknown flag only leaves
// the peel pointing at the wrong word, which classifies as unknown, never auto.
var wrappers = map[string]wrapper{
	"sudo":            {value: "-u -g -h -p -C -r -t -T -U -D -R --user --group --host --prompt --role --type --chdir --chroot --other-user --command-timeout --close-from"},
	"env":             {value: "-u -C --unset --chdir"},
	"nice":            {value: "-n --adjustment"},
	"ionice":          {value: "-c -n --class --classdata"},
	"timeout":         {value: "-k -s --kill-after --signal", positional: 1},
	"stdbuf":          {value: "-i -o -e --input --output --error"},
	"taskset":         {positional: 1},
	"chrt":            {positional: 1},
	"flock":           {value: "-w -E --timeout --conflict-exit-code", positional: 1},
	"cgexec":          {value: "-g"},
	"systemd-inhibit": {value: "--what --who --why --mode"},
	"time":            {value: "-o -f --output --format"},
	"nohup":           {},
	"setsid":          {},
	"command":         {},
	"builtin":         {},
	"busybox":         {},
	"toybox":          {},
	"coproc":          {},
	"unbuffer":        {},
}

var (
	readVerbs      = set(`status is-active is-enabled is-failed list-units list-unit-files list-timers list-sockets list-dependencies get-default`)
	hostPowerVerbs = set(`poweroff reboot halt suspend hibernate hybrid-sleep kexec rescue emergency`)

	// Stopping any of these can cut the owner off from the machine, or turn
	// off the agent that reports what is happening.
	protectedService = regexp.MustCompile(`(?i)^(open)?(ssh|sshd|dropbear|firewalld|ufw|nftables|iptables|ip6tables|fail2ban|greenserver|sudo|networking|network-manager|networkmanager|systemd-networkd|systemd-resolved)([.@-]|$)`)

	setuidMode = regexp.MustCompile(`^(.*\+s.*|0?[1-7][0-7]{3})$`)
	bsdCluster = regexp.MustCompile(`^[a-zA-Z]+$`)
	procMem    = regexp.MustCompile(`^/proc/[^/]+/mem$`)
	dotEnv     = regexp.MustCompile(`^\.env($|[._-])`)
	rawDisk    = regexp.MustCompile(`^/dev/(sd|hd|vd|xvd|nvme|mmcblk|dm-|md|loop|mem$|kmem$|port$)`)

	dangerousEnv = regexp.MustCompile(`^(LD_.*|DYLD_.*|BASH_ENV|ENV|IFS|PATH|SHELLOPTS|BASHOPTS|PS[0-9]|PROMPT_COMMAND|NODE_OPTIONS|PYTHONPATH|PYTHONSTARTUP|PERL5OPT|PERL5LIB|RUBYOPT|PAGER|SYSTEMD_PAGER|SYSTEMD_EDITOR|LESSOPEN|LESSCLOSE|EDITOR|VISUAL)$`)
	harmlessEnv  = regexp.MustCompile(`^(LANG|LANGUAGE|LC_[A-Z]+|TZ|TERM|COLUMNS|LINES|NO_COLOR)$`)
)

var (
	secretNames = set(`
		.env .envrc shadow gshadow shadow- gshadow- environment credentials .credentials.json .netrc
		.pgpass .my.cnf .git-credentials .npmrc .pypirc .htpasswd .bash_history .zsh_history
		.mysql_history .psql_history environ sudoers master.key .claude.json agent.sock audit.jsonl
		authorized_keys
	`)
	secretDirs       = set(`.ssh .aws .gnupg .azure .kube .docker .gcloud gcloud`)
	secretSuffixes   = []string{".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".ppk", ".gpg", ".kdbx", ".tfstate"}
	secretSubstrings = []string{"secret", "credential", "password", "apikey", "api_key"}
	secretPrefixes   = []string{"/etc/ssl/private", "/etc/letsencrypt/live", "/etc/letsencrypt/archive", "/etc/greenserver", "/etc/sudoers.d"}

	// secretExamples are what a glob or a run-time word is tested against.
	secretExamples = []string{
		".env", ".env.local", ".env.production", ".envrc", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
		"shadow", "gshadow", "environment", "environ", "credentials", ".credentials.json", ".netrc", ".pgpass",
		".my.cnf", ".git-credentials", ".npmrc", ".pypirc", ".htpasswd", ".bash_history", "sudoers",
		"server.pem", "server.key", "secrets.json", "client_secret", "password.txt", "api_key", "authorized_keys",
		"agent.sock", "audit.jsonl",
	}

	protectedPrefixes = []string{
		"/etc/ssh", "/etc/sudoers", "/etc/sudoers.d", "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
		"/etc/pam.d", "/etc/ufw", "/etc/firewalld", "/etc/iptables", "/etc/nftables.conf", "/etc/hosts.allow",
		"/etc/hosts.deny", "/etc/fstab", "/etc/greenserver", "/var/lib/greenserver", "/boot",
		"/etc/systemd/system/greenserver.service", "/lib/systemd/system/ssh.service",
	}
	protectedNames = set(`sshd_config ssh_config authorized_keys known_hosts sudoers nftables.conf`)
)
