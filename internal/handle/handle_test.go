package handle

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestParseTable(t *testing.T) {
	for _, ps := range []int{4, 8} {
		t.Run(fmt.Sprint(ps), func(t *testing.T) {
			buf := make([]byte, ps*2+ps*3+16)
			put := func(b []byte, v uint64) {
				if ps == 8 {
					binary.LittleEndian.PutUint64(b, v)
				} else {
					binary.LittleEndian.PutUint32(b, uint32(v))
				}
			}
			put(buf, 1)
			b := buf[ps*2:]
			put(b, 0x1122) // object, not a pointer to a name string
			put(b[ps:], 123)
			put(b[2*ps:], 456)
			binary.LittleEndian.PutUint32(b[3*ps:], 0x120089)
			binary.LittleEndian.PutUint16(b[3*ps+6:], 37)
			entries, err := parseTable(buf, ps)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0] != (entry{pid: 123, value: 456, access: 0x120089, typeIndex: 37}) {
				t.Fatalf("wrong ABI parse: %+v", entries)
			}
			if _, err := parseTable(buf[:len(buf)-1], ps); err == nil {
				t.Fatal("accepted truncated table")
			}
			put(buf, ^uint64(0))
			if _, err := parseTable(buf, ps); err == nil {
				t.Fatal("accepted unbounded count")
			}
		})
	}
	for _, ps := range []int{0, 4, 8, 16} {
		if _, err := parseTable(nil, ps); err == nil {
			t.Fatalf("accepted invalid header, pointer size %d", ps)
		}
	}
}

func FuzzParseTable(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0})
	f.Add(make([]byte, 16))
	f.Fuzz(func(t *testing.T, buf []byte) {
		for _, ps := range []int{4, 8} {
			_, _ = parseTable(buf, ps)
		}
	})
}

// The child opens only a synthetic fixture and holds it without reading it.
func TestFixtureHolder(t *testing.T) {
	if os.Getenv("COOKIEGUARD_TEST_HELPER") != "1" {
		return
	}
	flags := os.O_RDONLY
	if os.Getenv("COOKIEGUARD_TEST_WRITE_ONLY") == "1" {
		flags = os.O_WRONLY
	}
	f, err := os.OpenFile(os.Getenv("COOKIEGUARD_TEST_FILE"), flags, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fmt.Println("fixture-ready")
	_, _ = io.Copy(io.Discard, os.Stdin)
}

func holder(t *testing.T, path string, writeOnly bool) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestFixtureHolder$", "-test.timeout=30s")
	cmd.Env = append(os.Environ(), "COOKIEGUARD_TEST_HELPER=1", "COOKIEGUARD_TEST_FILE="+path)
	if writeOnly {
		cmd.Env = append(cmd.Env, "COOKIEGUARD_TEST_WRITE_ONLY=1")
	}
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		input.Close()
		if err := cmd.Wait(); err != nil {
			t.Errorf("fixture child: %v", err)
		}
	})
	line, err := bufio.NewReader(output).ReadString('\n')
	if err != nil || line != "fixture-ready\n" {
		t.Fatalf("helper not ready: %q, %v", line, err)
	}
	return cmd
}

func TestScanReadableHandleIntegration(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "synthetic-Cookies")
	other := filepath.Join(dir, "unrelated")
	for _, path := range []string{file, other} {
		if err := os.WriteFile(path, []byte("synthetic data only"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	child := holder(t, file, false)
	var scanner Scanner
	start := time.Now()
	report, err := scanner.Scan([]string{file, other})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("scan=%s handles=%d checked=%d inaccessible=%d unresolved=%d", time.Since(start), report.Handles, report.Checked, report.InaccessibleProcesses, report.UnresolvedHandles)
	found := false
	for _, o := range report.Observations {
		if o.Process.PID != child.Process.Pid {
			continue
		}
		if o.File != file || o.Process.Path == "" || o.Process.StartTime == 0 {
			t.Fatalf("incorrect observation: %+v", o)
		}
		found = true
	}
	if !found {
		t.Fatalf("did not detect fixture child PID %d: %+v", child.Process.Pid, report)
	}
	// A missing target must be visible as a coverage gap, never "clean".
	report, err = scanner.Scan([]string{filepath.Join(dir, "missing")})
	if err != nil || len(report.UnavailableTargets) != 1 {
		t.Fatalf("missing target: %+v %v", report, err)
	}
}

func TestScanWriteOnlyIsNotReadable(t *testing.T) {
	file := filepath.Join(t.TempDir(), "fixture")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	child := holder(t, file, true)
	var scanner Scanner
	report, err := scanner.Scan([]string{file})
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range report.Observations {
		if o.Process.PID == child.Process.Pid {
			t.Fatal("write-only handle reported as readable")
		}
	}
}

func TestScanHardLinkIdentity(t *testing.T) {
	dir := t.TempDir()
	file, link := filepath.Join(dir, "fixture"), filepath.Join(dir, "alias")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(file, link); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	child := holder(t, link, false)
	var scanner Scanner
	report, err := scanner.Scan([]string{file})
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range report.Observations {
		if o.Process.PID == child.Process.Pid && o.File == file {
			return
		}
	}
	t.Fatal("hard link access did not match file identity")
}
