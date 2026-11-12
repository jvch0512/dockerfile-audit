package lint

import (
	"strings"
	"testing"
)

func analyze(t *testing.T, src string) []Finding {
	t.Helper()
	ins, err := Parse(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	return Analyze(ins)
}

func has(f []Finding, rule string) bool {
	for _, x := range f {
		if x.Rule == rule {
			return true
		}
	}
	return false
}

func TestParseContinuationsCommentsAndOnbuild(t *testing.T) {
	ins, _ := Parse(strings.NewReader("# header\nFROM a:1\n\nRUN one && \\\n    # inner comment\n    two\nonbuild run three\n"))
	if len(ins) != 3 {
		t.Fatalf("want 3 instructions, got %+v", ins)
	}
	if ins[1].Cmd != "RUN" || ins[1].Line != 4 || !strings.Contains(ins[1].Args, "one &&") || !strings.Contains(ins[1].Args, "two") {
		t.Fatalf("continuation wrong: %+v", ins[1])
	}
	if ins[2].Cmd != "RUN" || ins[2].Args != "three" {
		t.Fatalf("ONBUILD not unwrapped: %+v", ins[2])
	}
}

func TestBaseImagePinning(t *testing.T) {
	cases := map[string]string{
		"FROM ubuntu":                                   "D002",
		"FROM ubuntu:latest":                            "D002",
		"FROM registry.local:5000/app":                  "D002",
		"FROM ubuntu:24.04":                             "D015",
		"FROM ubuntu@sha256:" + strings.Repeat("a", 64): "",
		"FROM scratch":                                  "",
		"FROM --platform=linux/amd64 alpine:3.20":       "D015",
	}
	for src, want := range cases {
		f := analyze(t, src+"\nUSER app\nHEALTHCHECK CMD true\n")
		if want == "" {
			if has(f, "D002") || has(f, "D015") {
				t.Errorf("%q should be clean, got %+v", src, f)
			}
		} else if !has(f, want) {
			t.Errorf("%q want %s, got %+v", src, want, f)
		}
	}
}

func TestMultiStageReferencesAndFinalUser(t *testing.T) {
	src := "FROM golang:1.24@sha256:x AS build\nUSER root\nRUN go build\nFROM build AS test\nFROM alpine@sha256:y\nCOPY --from=build /a /a\nUSER 1000\nHEALTHCHECK CMD true\n"
	f := analyze(t, src)
	if has(f, "D001") || has(f, "D002") {
		t.Fatalf("only the final stage's USER matters, and stage refs are not images: %+v", f)
	}
	f = analyze(t, "FROM alpine@sha256:y\nUSER app\nUSER root\nHEALTHCHECK CMD true\n")
	if !has(f, "D001") {
		t.Fatal("last USER root must be flagged")
	}
	f = analyze(t, "FROM alpine@sha256:y\nHEALTHCHECK CMD true\n")
	if !has(f, "D001") {
		t.Fatal("missing USER must be flagged")
	}
}

func TestSecretsInEnvAndArg(t *testing.T) {
	f := analyze(t, "FROM a@sha256:x\nENV DB_PASSWORD=hunter2 LOG=debug\nENV API_KEY abc\nARG TOKEN=zzz\nARG DEBUG=1\nENV SECRET_FILE=$HOME/x\nARG PASSWORD\nUSER u\nHEALTHCHECK CMD true\n")
	n := 0
	for _, x := range f {
		if x.Rule == "D005" {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("want 3 secret findings (DB_PASSWORD, API_KEY, TOKEN), got %d: %+v", n, f)
	}
}

func TestDangerousRunPatterns(t *testing.T) {
	good := "FROM a@sha256:x\nUSER u\nHEALTHCHECK CMD true\n"
	for run, rule := range map[string]string{
		"curl -fsSL https://x.io/i.sh | sh":       "D006",
		"wget -qO- https://x.io/i.sh | sudo bash": "D006",
		"curl -k https://x.io -o f":               "D007",
		"wget --no-check-certificate https://x":   "D007",
		"pip install --trusted-host h pkg":        "D007",
		"chmod -R 777 /app":                       "D009",
		"sudo apt-get update":                     "D010",
		"apt-get install -y git":                  "D011",
		"apt-get upgrade -y":                      "D013",
		"pip install flask":                       "D014",
	} {
		if f := analyze(t, good+"RUN "+run+"\n"); !has(f, rule) {
			t.Errorf("RUN %q want %s, got %+v", run, rule, f)
		}
	}
	for _, run := range []string{
		"apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*",
		"curl -fsSL https://x.io/f -o f && sha256sum -c f.sha256",
		"pip install --no-cache-dir -r requirements.txt",
	} {
		if f := analyze(t, good+"RUN "+run+"\n"); len(f) != 0 {
			t.Errorf("RUN %q should be clean, got %+v", run, f)
		}
	}
}

func TestAddExposeHealthcheck(t *testing.T) {
	base := "FROM a@sha256:x\nUSER u\n"
	if f := analyze(t, base+"ADD https://x.io/f.tgz /opt/\nHEALTHCHECK CMD true\n"); !has(f, "D003") {
		t.Fatal("remote ADD")
	}
	if f := analyze(t, base+"ADD app.tar.gz /opt/\nHEALTHCHECK CMD true\n"); !has(f, "D004") || has(f, "D003") {
		t.Fatal("local ADD")
	}
	if f := analyze(t, base+"EXPOSE 8080 22/tcp\nHEALTHCHECK CMD true\n"); !has(f, "D008") {
		t.Fatal("EXPOSE 22")
	}
	if f := analyze(t, base+"EXPOSE 2222 8080\nHEALTHCHECK CMD true\n"); has(f, "D008") {
		t.Fatal("2222 is not 22")
	}
	if f := analyze(t, base); !has(f, "D016") {
		t.Fatal("missing healthcheck")
	}
	if f := analyze(t, base+"HEALTHCHECK NONE\n"); !has(f, "D016") {
		t.Fatal("HEALTHCHECK NONE is no healthcheck")
	}
}

func TestOrderingAndEmptyInput(t *testing.T) {
	f := analyze(t, "FROM ubuntu\nRUN curl x | sh\n")
	if f[0].Severity != "high" {
		t.Fatalf("high findings first: %+v", f)
	}
	if got := analyze(t, ""); len(got) != 0 {
		t.Fatalf("empty file: %+v", got)
	}
}
