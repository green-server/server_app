package classify

import (
	"errors"
	"regexp"
	"strings"
)

// word is one shell word after quote removal.
type word struct {
	text    string // dequoted; expansions stay in raw form
	scan    string // text with every unknowable part replaced by '*', for secret matching
	dynamic bool   // value is only known at run time
	glob    bool   // contains unquoted pathname-expansion characters
}

type redirect struct {
	op     string
	target word
}

// simple is one command between control operators.
type simple struct {
	words     []word
	redirects []redirect
}

// script is a parsed command line. It over-approximates the shell on purpose:
// every operator splits, and a heredoc body is read as more commands, so
// anything that might run is looked at.
type script struct {
	cmds []simple
	subs []string // bodies of $(), backticks, <() and >()
	body string   // source without the trailing undo comment
	undo string   // payload of a trailing "# undo: ..." comment
}

var errParse = errors.New("cannot parse command")

var undoComment = regexp.MustCompile(`^#\s*undo:\s*(.*?)\s*$`)

// safeVars expand to values that are not secrets and are not worth blocking.
var safeVars = map[string]bool{
	"HOME": true, "USER": true, "LOGNAME": true, "PWD": true, "HOSTNAME": true, "PATH": true,
	"?": true, "$": true, "!": true, "#": true,
}

type parser struct {
	src     string
	i       int
	out     *script
	cur     simple
	w       word
	inWord  bool
	pending string // redirect operator waiting for its target
}

func parse(src string) (*script, error) {
	for i := 0; i < len(src); i++ {
		if c := src[i]; c < 0x20 && c != '\t' && c != '\n' || c == 0x7f {
			return nil, errParse
		}
	}
	p := &parser{src: src, out: &script{body: src}}
	for p.i < len(src) {
		c := src[p.i]
		switch {
		case c == ' ' || c == '\t':
			p.endWord()
			p.i++
		case c == '\n' || c == ';' || c == '(' || c == ')':
			if err := p.endCmd(); err != nil {
				return nil, err
			}
			p.i++
		case c == '&' && p.peek(1) == '>':
			p.endWord()
			p.i++
			if err := p.redirect("&"); err != nil {
				return nil, err
			}
		case c == '&' || c == '|':
			if err := p.endCmd(); err != nil {
				return nil, err
			}
			p.i++
		case c == '<' || c == '>':
			if err := p.redirect(""); err != nil {
				return nil, err
			}
		case c == '#' && !p.inWord:
			p.comment()
		default:
			if err := p.wordPart(); err != nil {
				return nil, err
			}
		}
	}
	if err := p.endCmd(); err != nil {
		return nil, err
	}
	return p.out, nil
}

func (p *parser) peek(n int) byte {
	if p.i+n < len(p.src) {
		return p.src[p.i+n]
	}
	return 0
}

func (p *parser) endWord() {
	if !p.inWord {
		return
	}
	if p.pending != "" {
		p.cur.redirects = append(p.cur.redirects, redirect{p.pending, p.w})
		p.pending = ""
	} else {
		p.cur.words = append(p.cur.words, p.w)
	}
	p.w, p.inWord = word{}, false
}

func (p *parser) endCmd() error {
	p.endWord()
	if p.pending != "" {
		return errParse
	}
	if len(p.cur.words)+len(p.cur.redirects) > 0 {
		p.out.cmds = append(p.out.cmds, p.cur)
	}
	p.cur = simple{}
	return nil
}

func (p *parser) lit(s string) {
	p.w.text += s
	p.w.scan += s
	p.inWord = true
}

func (p *parser) expansion(raw, scan string, dynamic bool) {
	p.w.text += raw
	p.w.scan += scan
	p.w.dynamic = p.w.dynamic || dynamic
	p.inWord = true
}

// comment consumes a comment. A "# undo:" comment counts only as the final
// content of the command, so it can never hide anything after it.
func (p *parser) comment() {
	end := strings.IndexByte(p.src[p.i:], '\n')
	text := p.src[p.i:]
	if end >= 0 {
		text = p.src[p.i : p.i+end]
	}
	if m := undoComment.FindStringSubmatch(text); m != nil && strings.TrimSpace(p.src[p.i+len(text):]) == "" {
		p.out.undo = m[1]
		p.out.body = strings.TrimSpace(p.src[:p.i])
	}
	p.i += len(text)
}

func (p *parser) redirect(prefix string) error {
	// A word of digits touching the operator is a file descriptor: 2>file.
	if p.inWord && p.w.text != "" && strings.Trim(p.w.text, "0123456789") == "" {
		p.w, p.inWord = word{}, false
	}
	p.endWord()
	start := p.i
	for p.i < len(p.src) && strings.IndexByte("<>&|-", p.src[p.i]) >= 0 {
		if p.src[p.i] == '-' && !strings.HasPrefix(p.src[start:p.i], "<<") {
			break
		}
		p.i++
	}
	op := p.src[start:p.i]
	if p.peek(0) == '(' && (op == "<" || op == ">") { // process substitution
		body, err := p.balanced(p.i + 1)
		if err != nil {
			return err
		}
		p.out.subs = append(p.out.subs, body)
		p.expansion("<(...)", "*", true)
		return nil
	}
	if p.pending != "" {
		return errParse
	}
	p.pending = prefix + op
	return nil
}

// balanced returns the text up to the ')' closing a group whose body starts
// at from, and moves past it.
func (p *parser) balanced(from int) (string, error) {
	depth, quote := 1, byte(0)
	for j := from; j < len(p.src); j++ {
		c := p.src[j]
		switch {
		case c == '\\' && quote != '\'':
			j++
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '(':
			depth++
		case c == ')':
			if depth--; depth == 0 {
				p.i = j + 1
				return p.src[from:j], nil
			}
		}
	}
	return "", errParse
}

func (p *parser) wordPart() error {
	c := p.src[p.i]
	switch c {
	case '\\':
		if p.i+1 >= len(p.src) {
			return errParse
		}
		if next := p.src[p.i+1]; next != '\n' {
			p.lit(string(next))
		}
		p.i += 2
	case '\'':
		end := strings.IndexByte(p.src[p.i+1:], '\'')
		if end < 0 {
			return errParse
		}
		p.lit(p.src[p.i+1 : p.i+1+end])
		p.i += end + 2
	case '"':
		p.i++
		return p.doubleQuoted()
	case '$':
		return p.dollar()
	case '`':
		return p.backtick()
	case '{':
		return p.brace()
	case '*', '?', '[':
		p.w.glob = true
		p.lit(string(c))
		p.i++
	default:
		p.lit(string(c))
		p.i++
	}
	return nil
}

func (p *parser) doubleQuoted() error {
	p.inWord = true
	for p.i < len(p.src) {
		c := p.src[p.i]
		switch c {
		case '"':
			p.i++
			return nil
		case '\\':
			if p.i+1 >= len(p.src) {
				return errParse
			}
			next := p.src[p.i+1]
			if strings.IndexByte("$`\"\\", next) >= 0 {
				p.lit(string(next))
			} else if next != '\n' {
				p.lit("\\" + string(next))
			}
			p.i += 2
		case '$':
			if err := p.dollar(); err != nil {
				return err
			}
		case '`':
			if err := p.backtick(); err != nil {
				return err
			}
		default:
			p.lit(string(c))
			p.i++
		}
	}
	return errParse
}

func (p *parser) backtick() error {
	var b strings.Builder
	for j := p.i + 1; j < len(p.src); j++ {
		c := p.src[j]
		if c == '`' {
			p.out.subs = append(p.out.subs, b.String())
			p.expansion("`...`", "*", true)
			p.i = j + 1
			return nil
		}
		if c == '\\' && j+1 < len(p.src) {
			j++
			c = p.src[j]
		}
		b.WriteByte(c)
	}
	return errParse
}

func (p *parser) dollar() error {
	next := p.peek(1)
	switch {
	case next == '\'': // ANSI-C quoting can spell any byte; refuse rather than decode.
		return errParse
	case next == '"':
		p.i++
		return nil
	case next == '(':
		body, err := p.balanced(p.i + 2)
		if err != nil {
			return err
		}
		p.out.subs = append(p.out.subs, body)
		p.expansion("$(...)", "*", true)
		return nil
	case next == '{':
		end := strings.IndexByte(p.src[p.i:], '}')
		if end < 0 {
			return errParse
		}
		body := p.src[p.i+2 : p.i+end]
		if strings.ContainsAny(body, "$`") { // ${x:-$(cmd)} hides a substitution
			return errParse
		}
		p.variable(body, p.src[p.i:p.i+end+1])
		p.i += end + 1
		return nil
	case strings.IndexByte("?$!#@*-", next) >= 0 && next != 0:
		p.variable(string(next), p.src[p.i:p.i+2])
		p.i += 2
		return nil
	}
	j := p.i + 1
	for j < len(p.src) && (p.src[j] == '_' || p.src[j] >= '0' && p.src[j] <= '9' ||
		p.src[j] >= 'a' && p.src[j] <= 'z' || p.src[j] >= 'A' && p.src[j] <= 'Z') {
		j++
	}
	if j == p.i+1 { // a lone dollar sign is a literal
		p.lit("$")
		p.i++
		return nil
	}
	p.variable(p.src[p.i+1:j], p.src[p.i:j])
	p.i = j
	return nil
}

func (p *parser) variable(name, raw string) {
	if safeVars[name] {
		p.expansion(raw, "x", false)
		return
	}
	p.expansion(raw, "*", true)
}

// brace handles {a,b} and {1..9}, which bash expands into several words.
func (p *parser) brace() error {
	end := strings.IndexByte(p.src[p.i:], '}')
	if end > 0 {
		body := p.src[p.i+1 : p.i+end]
		isGroup := strings.ContainsAny(body, " \t\n;&|()") // { cmd; } is a group, not an expansion
		if !isGroup && (strings.Contains(body, ",") || strings.Contains(body, "..")) {
			if strings.ContainsAny(body, "$`'\"\\") {
				return errParse
			}
			p.expansion(p.src[p.i:p.i+end+1], "*", true)
			p.i += end + 1
			return nil
		}
	}
	p.lit("{")
	p.i++
	return nil
}
