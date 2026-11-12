// Package lint parses Dockerfiles and applies security and hygiene rules.
package lint

import (
	"bufio"
	"io"
	"strings"
)

// Instruction is one logical Dockerfile instruction (continuations joined).
type Instruction struct {
	Line int    // first physical line
	Cmd  string // upper-case keyword, e.g. RUN
	Args string
}

// Parse joins backslash continuations, drops comments and blank lines, and unwraps ONBUILD.
func Parse(r io.Reader) ([]Instruction, error) {
	var out []Instruction
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var buf strings.Builder
	start, n := 0, 0
	flush := func() {
		text := strings.TrimSpace(buf.String())
		buf.Reset()
		if text == "" {
			return
		}
		cmd, args, _ := strings.Cut(text, " ")
		cmd = strings.ToUpper(cmd)
		args = strings.TrimSpace(args)
		if cmd == "ONBUILD" {
			cmd, args, _ = strings.Cut(args, " ")
			cmd = strings.ToUpper(cmd)
		}
		out = append(out, Instruction{Line: start, Cmd: cmd, Args: strings.TrimSpace(args)})
	}
	for sc.Scan() {
		n++
		line := sc.Text()
		trim := strings.TrimSpace(line)
		if buf.Len() == 0 && (trim == "" || strings.HasPrefix(trim, "#")) {
			continue
		}
		if buf.Len() > 0 && strings.HasPrefix(trim, "#") { // comment inside a continued instruction
			continue
		}
		if buf.Len() == 0 {
			start = n
		}
		if strings.HasSuffix(trim, "\\") {
			buf.WriteString(strings.TrimSuffix(trim, "\\") + " ")
			continue
		}
		buf.WriteString(trim)
		flush()
	}
	flush()
	return out, sc.Err()
}
