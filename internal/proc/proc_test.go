package proc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
