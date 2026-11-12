package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/jvch0512/dockerfile-audit/lint"
)

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func run(args []string, stdin io.Reader, out, errw io.Writer) int {
	fs := flag.NewFlagSet("dockerfile-audit", flag.ContinueOnError)
	fs.SetOutput(errw)
	asJSON := fs.Bool("json", false, "JSON output")
	failOn := fs.String("fail-on", "medium", "exit 1 at this severity or worse: low|medium|high")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rank := map[string]int{"low": 1, "medium": 2, "high": 3}
	threshold := rank[*failOn]
	if threshold == 0 || fs.NArg() == 0 {
		fmt.Fprintln(errw, "usage: dockerfile-audit [-json] [-fail-on low|medium|high] <Dockerfile|-> ...")
		return 2
	}
	type fileResult struct {
		File     string         `json:"file"`
		Findings []lint.Finding `json:"findings"`
	}
	var results []fileResult
	worst := 0
	for _, name := range fs.Args() {
		var r io.Reader = stdin
		if name != "-" {
			f, err := os.Open(name)
			if err != nil {
				fmt.Fprintln(errw, "error:", err)
				return 2
			}
			defer f.Close()
			r = f
		}
		ins, err := lint.Parse(r)
		if err != nil {
			fmt.Fprintln(errw, "error:", err)
			return 2
		}
		fnd := lint.Analyze(ins)
		if fnd == nil {
			fnd = []lint.Finding{}
		}
		for _, f := range fnd {
			if rank[f.Severity] > worst {
				worst = rank[f.Severity]
			}
		}
		results = append(results, fileResult{name, fnd})
	}
	if *asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
	} else {
		total := 0
		for _, r := range results {
			for _, f := range r.Findings {
				fmt.Fprintf(out, "%s:%d [%s] %s %s\n    fix: %s\n", r.File, f.Line, f.Severity, f.Rule, f.Message, f.Fix)
				total++
			}
		}
		fmt.Fprintf(out, "%d finding(s) in %d file(s)\n", total, len(results))
	}
	if worst >= threshold {
		return 1
	}
	return 0
}
