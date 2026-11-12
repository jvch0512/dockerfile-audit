package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLISamplesAndExitCodes(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{filepath.Join("samples", "Dockerfile.bad")}, nil, &out, &errb); code != 1 {
		t.Fatalf("bad sample should fail, got %d\n%s", code, out.String())
	}
	for _, id := range []string{"D001", "D002", "D003", "D005", "D006", "D007", "D008", "D009"} {
		if !strings.Contains(out.String(), id) {
			t.Errorf("sample output missing %s", id)
		}
	}
	out.Reset()
	if code := run([]string{filepath.Join("samples", "Dockerfile.good")}, nil, &out, &errb); code != 0 {
		t.Fatalf("good sample should pass, got %d\n%s", code, out.String())
	}
}

func TestCLIJSONStdinAndThreshold(t *testing.T) {
	var out, errb bytes.Buffer
	src := "FROM ubuntu:24.04\nUSER app\nHEALTHCHECK CMD true\n" // only a low finding (tag-only pin)
	if code := run([]string{"-json", "-"}, strings.NewReader(src), &out, &errb); code != 0 {
		t.Fatalf("low finding passes the default threshold, got %d", code)
	}
	var res []struct {
		File     string
		Findings []struct{ Rule string }
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil || len(res) != 1 || res[0].Findings[0].Rule != "D015" {
		t.Fatalf("bad JSON %v: %s", err, out.String())
	}
	if code := run([]string{"-fail-on", "low", "-"}, strings.NewReader(src), &out, &errb); code != 1 {
		t.Fatalf("low threshold should fail, got %d", code)
	}
}

func TestCLIErrors(t *testing.T) {
	var out, errb bytes.Buffer
	if run(nil, nil, &out, &errb) != 2 || run([]string{"-fail-on", "bogus", "x"}, nil, &out, &errb) != 2 || run([]string{"/does/not/exist"}, nil, &out, &errb) != 2 {
		t.Fatal("usage and I/O errors must exit 2")
	}
	p := filepath.Join(t.TempDir(), "Dockerfile")
	_ = os.WriteFile(p, []byte("FROM scratch\nUSER 1\nHEALTHCHECK CMD true\n"), 0o600)
	if run([]string{p}, nil, &out, &errb) != 0 {
		t.Fatal("clean file should pass")
	}
}
