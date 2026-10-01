package proc

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCurrentProcessAPIs(t *testing.T) {
	pid := uint32(os.Getpid())
	entries, err := Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.PID == pid {
			found = true
		}
	}
	if !found {
		t.Fatal("current process missing from snapshot")
	}
	image, err := ImagePath(pid)
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(filepath.Clean(image), filepath.Clean(exe)) {
		t.Fatalf("wrong image: %q != %q", image, exe)
	}
	start, err := StartTime(pid)
	if err != nil || start <= 0 {
		t.Fatalf("invalid creation time: %d %v", start, err)
	}
	command, err := CommandLine(pid)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(command), strings.ToLower(filepath.Base(exe))) {
		t.Fatalf("wrong command line: %q", command)
	}
}

func TestDescendantsIncludesChild(t *testing.T) {
	cmd := exec.Command("cmd.exe", "/c", "ping", "-n", "6", "127.0.0.1")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start child: %v", err)
	}
	defer func() { _ = cmd.Process.Kill() }()
	time.Sleep(600 * time.Millisecond)
	descendants := Descendants(uint32(os.Getpid()))
	for _, d := range descendants {
		if d == uint32(cmd.Process.Pid) {
			return
		}
	}
	t.Fatalf("direct child %d not found in %v", cmd.Process.Pid, descendants)
}
