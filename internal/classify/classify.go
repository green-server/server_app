// Package classify decides the permission tier of what Claude wants to do.
// It is pure: it never touches the filesystem, the environment or a process.
//
// Tiers only ever go up. There is deliberately no approve list: anything not
// proven safe by the auto table is approve, and anything matching a deny rule
// is deny, so a command nobody thought of can never come out as auto.
package classify

import (
	"encoding/json"
	"path"
	"regexp"
	"strings"
)

type Tier string

const (
	Auto    Tier = "auto"
	Approve Tier = "approve"
	Deny    Tier = "deny"
)

func rank(t Tier) int {
	switch t {
	case Auto:
		return 0
	case Approve:
		return 1
	}
	return 2 // anything unexpected counts as deny
}

const (
	maxDepth   = 6
	maxCommand = 64 * 1024
)

// Verdict is the decision on one tool call.
type Verdict struct {
	Tier    Tier
	Reason  string
	Command string // the action, without the undo comment
	Undo    string
	// Blocked is set on an approve-tier call that may not even be asked,
	// because it has no usable undo command. Deny tier is always blocked too.
	Blocked bool
}

// Evaluate is the single gate shared by the hook, the MCP tool and the agent.
// Only Bash and Read exist as far as Green Server is concerned.
func Evaluate(tool string, input json.RawMessage) Verdict {
	var in struct {
		Command  string `json:"command"`
		FilePath string `json:"file_path"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return Verdict{Tier: Deny, Reason: "unreadable tool input", Blocked: true}
	}
	switch tool {
	case "Read":
		v := Verdict{Tier: Auto, Command: "Read " + in.FilePath}
		if in.FilePath == "" || secretPath(in.FilePath, false) {
			v.Tier, v.Reason, v.Blocked = Deny, "secret file", true
		}
		return v
	case "Bash":
		return evaluateBash(in.Command)
	}
	return Verdict{Tier: Deny, Reason: "tool not allowed: " + tool, Command: tool, Blocked: true}
}

func evaluateBash(command string) Verdict {
	v := Verdict{Command: command}
	if strings.TrimSpace(command) == "" || len(command) > maxCommand {
		v.Tier, v.Reason, v.Blocked = Deny, "empty or oversized command", true
		return v
	}
	v.Tier, v.Reason = Command(command)
	if s, err := parse(command); err == nil {
		v.Command, v.Undo = s.body, s.undo
	}
	switch v.Tier {
	case Deny:
		v.Blocked = true
	case Approve:
		if why := undoProblem(v.Undo); why != "" {
			v.Blocked, v.Reason = true, why
		}
	}
	return v
}

// undoProblem explains why an undo command cannot back an action, or returns
// "". A real undo changes state again, so it must itself be approve tier: an
// auto-tier no-op such as "true" would satisfy the rule while undoing nothing,
// and a deny-tier one would become a way to run a denied command later.
func undoProblem(undo string) string {
	if undo == "" {
		return `approve-tier command needs an undo: end it with a comment "# undo: <command that reverts it>"`
	}
	switch t, why := Command(undo); t {
	case Approve:
		return ""
	case Auto:
		return "undo command must actually revert the change, this one changes nothing"
	default:
		return "undo command is not allowed: " + why
	}
}

// Command returns the strictest tier found anywhere in a shell command line.
func Command(src string) (Tier, string) {
	w := &walker{tier: Auto}
	w.script(src, 0)
	if w.downloads && w.execs {
		w.raise(Deny, "downloads and then executes code")
	}
	return w.tier, w.reason
}

type walker struct {
	tier      Tier
	reason    string
	downloads bool
	execs     bool
	probe     bool // deny-only re-check of a fragment; suppresses further probing
}

func (w *walker) raise(t Tier, why string) {
	if rank(t) > rank(w.tier) {
		w.tier, w.reason = t, why
	}
}

func (w *walker) script(src string, depth int) {
	if depth > maxDepth {
		w.raise(Deny, "nested too deeply")
		return
	}
	s, err := parse(src)
	if err != nil {
		if !w.probe {
			w.raise(Deny, "cannot parse command")
		}
		return
	}
	for _, c := range s.cmds {
		w.redirects(c.redirects)
		w.exec(c.words, depth)
	}
	for _, sub := range s.subs {
		w.script(sub, depth+1)
	}
}

func (w *walker) redirects(rs []redirect) {
	for _, r := range rs {
		target := r.target.text
		if strings.HasPrefix(target, "/dev/tcp") || strings.HasPrefix(target, "/dev/udp") {
			w.raise(Deny, "raw network redirect")
		}
		if strings.HasPrefix(r.op, "<<") {
			continue // a heredoc delimiter or here-string body is not a file
		}
		if referencesSecret(r.target.scan, r.target.dynamic || r.target.glob) {
			w.raise(Deny, "secret file")
		}
		if !strings.ContainsRune(r.op, '>') {
			continue
		}
		dup := (r.op == ">&" || r.op == "<&") && (target == "-" || strings.Trim(target, "0123456789") == "")
		if dup || target == "/dev/null" || target == "/dev/stdout" || target == "/dev/stderr" {
			continue
		}
		if protectedPath(target) {
			w.raise(Deny, "write to a protected path")
		}
		w.raise(Approve, "writes to a file")
	}
}

// exec classifies one simple command after peeling everything that merely
// launches another command.
func (w *walker) exec(all []word, depth int) {
	ws, wrapped := all, false
	for {
		ws = w.assignments(stripKeywords(ws))
		if len(ws) == 0 {
			break
		}
		if ws[0].dynamic || ws[0].glob {
			w.raise(Deny, "command name is not a literal")
			return
		}
		name := baseName(ws[0].text)
		wr, ok := wrappers[name]
		if !ok {
			break
		}
		if name == "command" && hasShort(texts(ws[1:]), "vV") {
			return
		}
		if strings.Contains(ws[0].text, "/") && !systemBinary(ws[0].text) {
			w.execs = true
			w.raise(Approve, "binary outside the system directories")
		}
		rest, why := wr.peel(name, ws)
		if why != "" {
			w.raise(Deny, why)
			return
		}
		ws, wrapped = rest, true
		if len(ws) == 0 {
			if name == "env" {
				w.raise(Deny, "prints the environment")
			} else if !(name == "sudo" && len(all) == 2 && all[1].text == "-l") {
				w.raise(Approve, "bare "+name)
			}
			break
		}
	}

	name := ""
	if len(ws) > 0 {
		name = baseName(ws[0].text)
	}
	meta := metadataOnly[name]
	for _, x := range all {
		if referencesSecret(x.scan, x.glob && !meta || x.dynamic && !meta) {
			w.raise(Deny, "secret file or value that cannot be resolved statically")
			return
		}
	}
	if len(ws) == 0 {
		return
	}

	tier, why := w.decide(name, ws[1:], depth)
	if tier == Auto {
		if strings.Contains(ws[0].text, "/") && !systemBinary(ws[0].text) {
			tier, why = Approve, "binary outside the system directories"
		}
		for _, x := range ws[1:] {
			if x.dynamic {
				tier, why = Approve, "argument only known at run time"
			}
		}
	}
	if strings.Contains(ws[0].text, "/") && !systemBinary(ws[0].text) {
		w.execs = true
	}
	if tier != Auto {
		for _, x := range all[1:] {
			if pathsIn(x.text, protectedPath) {
				tier, why = Deny, "touches a protected path"
			}
		}
	}
	w.raise(tier, why)
	if w.probe {
		return
	}

	// A wrapper flag we do not know can leave the real command further along.
	if wrapped {
		for j := 1; j < len(all); j++ {
			w.mustNotDeny(func(q *walker) { q.exec(all[j:], depth+1) })
		}
	}
	if tier == Auto {
		return
	}
	// Tools like watch or flock -c take a whole command as one word.
	for _, x := range all[1:] {
		if strings.ContainsAny(x.text, " \t") && !x.dynamic {
			w.mustNotDeny(func(q *walker) { q.script(x.text, depth+1) })
		}
	}
}

func (w *walker) mustNotDeny(check func(*walker)) {
	q := &walker{tier: Auto, probe: true}
	check(q)
	if q.tier == Deny {
		w.raise(Deny, q.reason)
	}
}

func stripKeywords(ws []word) []word {
	for len(ws) > 0 && shellKeywords[ws[0].text] && !ws[0].dynamic {
		ws = ws[1:]
	}
	return ws
}

var assignment = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\+?=`)

// assignments strips NAME=value prefixes.
func (w *walker) assignments(ws []word) []word {
	for len(ws) > 0 {
		m := assignment.FindStringSubmatch(ws[0].text)
		if m == nil {
			break
		}
		switch {
		case dangerousEnv.MatchString(m[1]):
			w.raise(Deny, "changes how programs load: "+m[1])
		case !harmlessEnv.MatchString(m[1]) && len(ws) > 1:
			w.raise(Approve, "unknown environment prefix: "+m[1])
		}
		ws = ws[1:]
	}
	return ws
}

// decide holds the per-command rules. The default is Approve.
func (w *walker) decide(name string, args []word, depth int) (Tier, string) {
	argv := texts(args)
	switch {
	case denied[name], strings.HasPrefix(name, "mkfs"), strings.HasPrefix(name, "iptables"), strings.HasPrefix(name, "ip6tables"):
		return Deny, "forbidden command: " + name
	case shells[name]:
		return w.shell(name, args, depth)
	case interpreter.MatchString(name):
		return interpreterRule(w, name, argv)
	case autoPlain[name]:
		return Auto, ""
	case downloaders[name]:
		w.downloads = true
	}

	switch name {
	case "rm":
		for _, a := range args {
			if a.dynamic {
				return Deny, "rm with a run-time argument"
			}
		}
		if hasShort(argv, "rR") || hasLong(argv, "--r", "--no-preserve-root") {
			return Deny, "recursive rm"
		}
	case "chmod", "chown", "chgrp":
		for _, a := range argv {
			if path.Clean(a) == "/" || setuidMode.MatchString(a) {
				return Deny, "dangerous ownership or mode change"
			}
		}
	case "kill", "pkill", "killall", "skill":
		for i, a := range argv {
			if protectedService.MatchString(a) || a == "1" || a == "-1" && i == len(argv)-1 && i > 0 {
				return Deny, "kills a protected process"
			}
		}
	case "systemctl":
		return systemctl(args)
	case "service":
		if len(argv) >= 2 && argv[1] == "status" {
			return Auto, ""
		}
		for _, a := range argv {
			if protectedService.MatchString(a) {
				return Deny, "changes a protected service"
			}
		}
	case "ps":
		return psRule(argv)
	case "journalctl":
		if !hasShort(argv, "f") && !hasLong(argv, "--follow", "--vacuum", "--rotate", "--flush", "--sync", "--relinquish", "--setup-keys", "--update-catalog") {
			return Auto, ""
		}
	case "grep", "egrep", "fgrep":
		if !hasShort(argv, "rRd") && !hasLong(argv, "--recursive", "--dereference-recursive", "--directories") {
			return Auto, ""
		}
	case "sort":
		if !hasShort(argv, "oT") && !hasLong(argv, "--output", "--compress-program", "--temporary-directory") {
			return Auto, ""
		}
	case "uniq":
		if len(positional(argv)) <= 1 {
			return Auto, ""
		}
	case "date":
		if !hasShort(argv, "s") && !hasLong(argv, "--set") {
			return Auto, ""
		}
	case "hostname":
		if onlyFrom(argv, "-f", "-i", "-I", "-s", "--fqdn", "--short", "--ip-address", "--all-ip-addresses") {
			return Auto, ""
		}
	case "dmesg":
		if !hasShort(argv, "cCDEn") && !hasLong(argv, "--clear", "--read-clear", "--console") {
			return Auto, ""
		}
	case "ss":
		if !hasShort(argv, "K") && !hasLong(argv, "--kill") {
			return Auto, ""
		}
	case "top":
		if hasShort(argv, "b") {
			return Auto, ""
		}
	case "ip":
		if ipReadOnly(argv) {
			return Auto, ""
		}
	case "nvidia-smi":
		if nvidiaReadOnly(argv) {
			return Auto, ""
		}
	case "crontab":
		if len(argv) == 1 && argv[0] == "-l" {
			return Auto, ""
		}
	case "cpupower":
		if len(argv) > 0 && (argv[0] == "frequency-info" || argv[0] == "idle-info" || argv[0] == "info") {
			return Auto, ""
		}
	case "powerprofilesctl":
		if len(argv) == 0 || argv[0] == "get" || argv[0] == "list" {
			return Auto, ""
		}
	case "docker":
		if len(argv) > 0 && argv[0] == "ps" {
			return Auto, ""
		}
		if len(argv) > 0 && argv[0] == "stats" && hasLong(argv, "--no-stream") {
			return Auto, ""
		}
	case "sed":
		return sedRule(argv)
	case "awk", "gawk", "mawk", "nawk":
		return awkRule(argv)
	case "find":
		return w.find(args, depth)
	case "xargs":
		return w.xargs(args, depth)
	}
	return Approve, "not known to be read-only: " + name
}

func (w *walker) shell(name string, args []word, depth int) (Tier, string) {
	for i, a := range args {
		t := a.text
		if t == "--" {
			args = args[i+1:]
			break
		}
		if !strings.HasPrefix(t, "-") || t == "-" || strings.HasPrefix(t, "--") {
			continue
		}
		if strings.ContainsRune(t, 'c') {
			for _, p := range args[i+1:] {
				if strings.HasPrefix(p.text, "-") {
					continue
				}
				if p.dynamic {
					return Deny, "shell payload is not a literal"
				}
				w.script(p.text, depth+1)
				return Auto, ""
			}
			return Deny, name + " -c without a payload"
		}
		if strings.ContainsRune(t, 's') {
			return Deny, name + " reading a program from stdin"
		}
	}
	for _, a := range args {
		if strings.HasPrefix(a.text, "-") && a.text != "-" {
			continue
		}
		if a.dynamic || a.text == "-" || strings.HasPrefix(a.text, "/dev/") {
			return Deny, name + " reading a program it cannot show"
		}
		w.execs = true
		return Approve, "runs a script"
	}
	return Deny, name + " reading a program from stdin"
}

func interpreterRule(w *walker, name string, argv []string) (Tier, string) {
	if hasShort(argv, "ceEr") || hasLong(argv, "--eval", "--exec", "--command", "--run") || len(positional(argv)) == 0 {
		return Deny, name + " with inline or piped code"
	}
	w.execs = true
	return Approve, "runs a script"
}

func systemctl(args []word) (Tier, string) {
	argv := texts(args)
	verb := ""
	if p := positional(argv); len(p) > 0 {
		verb = p[0]
	}
	if hostPowerVerbs[verb] {
		return Deny, "powers off the host"
	}
	if readVerbs[verb] {
		return Auto, ""
	}
	if verb == "show" {
		if hasShort(argv, "p") || hasLong(argv, "--property") {
			if !strings.Contains(strings.Join(argv, " "), "Environment") {
				return Auto, ""
			}
		}
		return Approve, "systemctl show can print service environment"
	}
	for _, a := range args {
		if protectedService.MatchString(a.text) {
			return Deny, "changes a protected service"
		}
		if a.dynamic || strings.ContainsAny(a.text, "*?[") {
			return Deny, "unit pattern could match a protected service"
		}
	}
	return Approve, "changes a service"
}

func psRule(argv []string) (Tier, string) {
	prev := ""
	for _, a := range argv {
		dump := strings.Contains(a, "env") ||
			strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.ContainsRune(a, 'E')
		cluster := !strings.HasPrefix(a, "-") && bsdCluster.MatchString(a) && strings.ContainsRune(a, 'e')
		isValue := strings.HasSuffix(prev, "o") || strings.HasSuffix(prev, "O")
		if dump || cluster && !isValue {
			return Deny, "prints process environments"
		}
		prev = a
	}
	return Auto, ""
}

var sedPrint = regexp.MustCompile(`^([0-9]+|\$)?(,([0-9]+|\$))?[pd]$`)

// sed is auto only for a script that visibly just prints lines. GNU sed's e
// and w commands execute and write, so a general script cannot be trusted.
func sedRule(argv []string) (Tier, string) {
	if hasLong(argv, "--in-place") || hasShort(argv, "ifs") {
		return Approve, "sed edits a file"
	}
	p := positional(argv)
	if len(p) == 0 || !sedPrint.MatchString(p[0]) {
		return Approve, "sed script is not a plain print"
	}
	return Auto, ""
}

func awkRule(argv []string) (Tier, string) {
	if hasShort(argv, "fiE") || hasLong(argv, "--file", "--include", "--load", "--exec") {
		return Approve, "awk program comes from a file"
	}
	p := positional(argv)
	if len(p) == 0 {
		return Approve, "awk without a program"
	}
	prog := p[0]
	if strings.Contains(prog, "ENVIRON") {
		return Deny, "awk reading the environment"
	}
	if strings.Contains(prog, "system") || strings.Contains(prog, "getline") || strings.ContainsAny(prog, "|>@") {
		return Approve, "awk program has side effects"
	}
	return Auto, ""
}

func (w *walker) find(args []word, depth int) (Tier, string) {
	tier, why := Auto, ""
	for i := 0; i < len(args); i++ {
		switch t := args[i].text; {
		case t == "-delete":
			return Deny, "find -delete"
		case t == "-exec" || t == "-execdir" || t == "-ok" || t == "-okdir":
			end := i + 1
			for end < len(args) && args[end].text != ";" && args[end].text != "+" {
				end++
			}
			w.exec(args[i+1:end], depth+1)
			i = end
			tier, why = Approve, "find runs a command"
		case strings.HasPrefix(t, "-fprint"), t == "-fls":
			tier, why = Approve, "find writes a file"
		}
	}
	return tier, why
}

func (w *walker) xargs(args []word, depth int) (Tier, string) {
	rest, _ := wrapper{value: "-I -n -P -L -d -s -E -a --max-args --max-procs --max-lines --delimiter --arg-file --replace"}.peel("xargs", append([]word{{}}, args...))
	if len(rest) > 0 {
		w.exec(rest, depth+1)
	}
	return Approve, "xargs feeds run-time input to a command"
}

var ipSubjects = map[string]bool{"a": true, "addr": true, "address": true, "r": true, "route": true, "l": true, "link": true, "n": true, "neigh": true}

func ipReadOnly(argv []string) bool {
	p := positional(argv)
	if len(p) == 0 || !ipSubjects[p[0]] || hasShort(argv, "bn") || hasLong(argv, "--batch", "--netns") {
		return false
	}
	return len(p) == 1 || p[1] == "show" || p[1] == "list" || p[1] == "ls"
}

var (
	nvidiaFlag  = regexp.MustCompile(`^(-q|-L|-x|-l|-lms|-i|-d|--query|--query-[a-z-]+=.*|--format=.*|--list-gpus|--id=.*|--display=.*|--loop=.*|--loop-ms=.*)$`)
	nvidiaValue = regexp.MustCompile(`^([0-9,]+|[A-Z_,]+|dmon|pmon)$`)
)

func nvidiaReadOnly(argv []string) bool {
	for _, a := range argv {
		if !nvidiaFlag.MatchString(a) && !nvidiaValue.MatchString(a) {
			return false
		}
	}
	return true
}

func texts(ws []word) []string {
	out := make([]string, len(ws))
	for i, x := range ws {
		out[i] = x.text
	}
	return out
}

func positional(argv []string) []string {
	var out []string
	for _, a := range argv {
		if !strings.HasPrefix(a, "-") {
			out = append(out, a)
		}
	}
	return out
}

// hasShort reports a short flag, also inside clusters such as -fr.
func hasShort(argv []string, letters string) bool {
	for _, a := range argv {
		if len(a) > 1 && a[0] == '-' && a[1] != '-' && strings.ContainsAny(a[1:], letters) {
			return true
		}
	}
	return false
}

// hasLong matches by prefix because GNU tools accept abbreviated long options.
func hasLong(argv []string, prefixes ...string) bool {
	for _, a := range argv {
		for _, p := range prefixes {
			if strings.HasPrefix(a, p) {
				return true
			}
		}
	}
	return false
}

func onlyFrom(argv []string, allowed ...string) bool {
	for _, a := range argv {
		ok := false
		for _, x := range allowed {
			ok = ok || a == x
		}
		if !ok {
			return false
		}
	}
	return true
}

func baseName(s string) string { return s[strings.LastIndexByte(s, '/')+1:] }

func systemBinary(s string) bool {
	for _, dir := range []string{"/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/local/bin/", "/usr/local/sbin/"} {
		if strings.HasPrefix(s, dir) && path.Clean(s) == s && strings.Count(s[len(dir):], "/") == 0 {
			return true
		}
	}
	return false
}

type wrapper struct {
	value      string // flags that take a separate value
	positional int    // leading operands before the wrapped command
}

// peel returns the wrapped command, or why the wrapper itself is refused.
func (wr wrapper) peel(name string, ws []word) ([]word, string) {
	takesValue := map[string]bool{}
	for _, f := range strings.Fields(wr.value) {
		takesValue[f] = true
	}
	i := 1
	for i < len(ws) {
		t := ws[i].text
		if t == "--" {
			i++
			break
		}
		if !strings.HasPrefix(t, "-") || t == "-" {
			break
		}
		short := !strings.HasPrefix(t, "--")
		if name == "sudo" && (short && strings.ContainsAny(t, "sie") || hasLong([]string{t}, "--shell", "--login", "--edit")) {
			return nil, "sudo opening a shell or editor"
		}
		if name == "env" && (short && strings.ContainsRune(t, 'S') || strings.HasPrefix(t, "--split-string")) {
			return nil, "env -S runs a string"
		}
		i++
		if takesValue[t] {
			i++
		}
	}
	i += wr.positional
	if i >= len(ws) {
		return nil, ""
	}
	return ws[i:], ""
}

// pathsIn applies check to every path-like piece of a word.
func pathsIn(s string, check func(string) bool) bool {
	for _, piece := range strings.FieldsFunc(s, func(r rune) bool { return strings.ContainsRune("=,:@;'\" ", r) }) {
		if check(piece) {
			return true
		}
	}
	return false
}

func referencesSecret(scan string, wild bool) bool {
	return pathsIn(scan, func(p string) bool { return secretPath(p, wild) })
}

func secretPath(p string, wild bool) bool {
	clean := strings.ToLower(path.Clean(p))
	if procMem.MatchString(clean) {
		return true
	}
	for _, prefix := range secretPrefixes {
		if clean == prefix || strings.HasPrefix(clean, prefix+"/") {
			return true
		}
	}
	comps := strings.Split(clean, "/")
	for _, c := range comps[:len(comps)-1] {
		if secretDirs[c] {
			return true
		}
	}
	base := comps[len(comps)-1]
	if secretDirs[base] || secretName(base) {
		return true
	}
	if !wild {
		return false
	}
	for _, c := range comps[:len(comps)-1] {
		if c == "*" || !strings.ContainsAny(c, "*?[") {
			continue
		}
		for dir := range secretDirs {
			if m, err := path.Match(c, dir); m || err != nil {
				return true
			}
		}
	}
	if strings.ContainsAny(base, "*?[") {
		for _, example := range secretExamples {
			if m, err := path.Match(base, example); m || err != nil {
				return true
			}
		}
	}
	return false
}

func secretName(base string) bool {
	if secretNames[base] || dotEnv.MatchString(base) || strings.HasPrefix(base, "ssh_host_") {
		return true
	}
	for _, s := range secretSuffixes {
		if strings.HasSuffix(base, s) {
			return true
		}
	}
	for _, s := range secretSubstrings {
		if strings.Contains(base, s) {
			return true
		}
	}
	return strings.HasPrefix(base, "id_rsa") || strings.HasPrefix(base, "id_dsa") ||
		strings.HasPrefix(base, "id_ecdsa") || strings.HasPrefix(base, "id_ed25519")
}

func protectedPath(p string) bool {
	clean := path.Clean(p)
	if rawDisk.MatchString(clean) {
		return true
	}
	for _, prefix := range protectedPrefixes {
		if clean == prefix || strings.HasPrefix(clean, prefix+"/") {
			return true
		}
	}
	return protectedNames[path.Base(clean)]
}
