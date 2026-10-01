package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cookieguard/internal/handle"
)

func TestCLI(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--help"}, {"scan", "--help"}} {
		var out, diag bytes.Buffer
		if err := run(args, &out, &diag); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	for _, args := range [][]string{{"nonsense"}, {"run", "--lang", "xx"}, {"run", "unexpected"}, {"scan", "--file", `C:\cookieguard-test-missing-file`}} {
		var out, diag bytes.Buffer
		if err := run(args, &out, &diag); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	for _, lang := range []string{"tr", "en"} {
		var out, diag bytes.Buffer
		err := run([]string{"scan", "--profile", t.TempDir(), "--lang", lang}, &out, &diag)
		want := "No browser cookie"
		if lang == "tr" {
			want = "Tarayıcı çerez"
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("wrong localized error: %v", err)
		}
	}
}

func TestScanEmitsMachineReadableJSON(t *testing.T) {
	file := filepath.Join(t.TempDir(), "synthetic-file")
	if err := os.WriteFile(file, []byte("synthetic fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	var out, diag bytes.Buffer
	if err := run([]string{"scan", "--file", file, "--lang", "en"}, &out, &diag); err != nil {
		t.Fatal(err)
	}
	var report handle.Report
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("stdout polluted with diagnostics: %v", err)
	}
	if report.Handles == 0 {
		t.Fatal("native handle scan did not run")
	}
	if !strings.Contains(diag.String(), "does not guarantee prevention") {
		t.Fatal("missing limitations warning")
	}
}
