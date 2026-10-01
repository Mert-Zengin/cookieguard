// Package proc wraps the Windows process APIs CookieGuard needs.
package proc

import (
	"errors"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Process is a lightweight entry from a process snapshot.
type Process struct {
	PID  uint32
	PPID uint32
	Name string // lower-case executable name, e.g. "chrome.exe"
}

// Snapshot returns all running processes.
func Snapshot() ([]Process, error) {
	h, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)

	var out []Process
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	for err = windows.Process32First(h, &e); err == nil; err = windows.Process32Next(h, &e) {
		out = append(out, Process{
			PID:  e.ProcessID,
			PPID: e.ParentProcessID,
			Name: strings.ToLower(windows.UTF16ToString(e.ExeFile[:])),
		})
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return out, err
	}
	return out, nil
}

// ImagePath returns the full executable path of a process.
func ImagePath(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:n]), nil
}

// CommandLine returns the command line of a process (Windows 8.1+).
func CommandLine(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)

	buf := make([]byte, 2048)
	for range 4 {
		var size uint32
		err = windows.NtQueryInformationProcess(h, windows.ProcessCommandLineInformation,
			unsafe.Pointer(&buf[0]), uint32(len(buf)), &size)
		if err == nil {
			us := (*windows.NTUnicodeString)(unsafe.Pointer(&buf[0]))
			return us.String(), nil
		}
		if !isBufferError(err) || int(size) <= len(buf) {
			return "", err
		}
		buf = make([]byte, size)
	}
	return "", err
}

func isBufferError(err error) bool {
	return errors.Is(err, windows.STATUS_INFO_LENGTH_MISMATCH) ||
		errors.Is(err, windows.STATUS_BUFFER_TOO_SMALL) ||
		errors.Is(err, windows.STATUS_BUFFER_OVERFLOW)
}

// StartTime returns the process creation time (100ns ticks). Combined with
// the PID it uniquely identifies a process even when PIDs are reused.
func StartTime(pid uint32) (int64, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(h)

	var c, e, k, u windows.Filetime
	if err := windows.GetProcessTimes(h, &c, &e, &k, &u); err != nil {
		return 0, err
	}
	return c.Nanoseconds(), nil
}

// ParentPID returns the creator PID using PROCESS_BASIC_INFORMATION. When the
// parent has exited, Windows may still report a reused or stale PID; callers
// must corroborate it with the parent's creation time before trusting it.
func ParentPID(pid uint32) (uint32, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(h)

	var pbi windows.PROCESS_BASIC_INFORMATION
	var size uint32
	if err := windows.NtQueryInformationProcess(h, windows.ProcessBasicInformation,
		unsafe.Pointer(&pbi), uint32(unsafe.Sizeof(pbi)), &size); err != nil {
		return 0, err
	}
	return uint32(pbi.InheritedFromUniqueProcessId), nil
}

// Descendants returns all processes whose parent chain leads back to pid.
// It is best-effort: a process that exits between the snapshot and the call is
// simply absent. A depth limit guards against a corrupted parent graph.
func Descendants(pid uint32) []uint32 {
	snap, err := Snapshot()
	if err != nil {
		return nil
	}
	children := make(map[uint32][]uint32)
	for _, p := range snap {
		children[p.PPID] = append(children[p.PPID], p.PID)
	}
	var out []uint32
	var walk func(uint32, int)
	walk = func(parent uint32, depth int) {
		if depth > 64 {
			return
		}
		for _, child := range children[parent] {
			out = append(out, child)
			walk(child, depth+1)
		}
	}
	walk(pid, 0)
	return out
}

// KillTree terminates a process and all of its descendants. Children are killed
// before the parent so an Electron/stealer child cannot outlive its loader.
// It returns the first error, if any.
func KillTree(pid uint32) error {
	descendants := Descendants(pid)
	var firstErr error
	for i := len(descendants) - 1; i >= 0; i-- {
		if err := Kill(descendants[i]); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if err := Kill(pid); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// Kill terminates a process.
func Kill(pid uint32) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.TerminateProcess(h, 1)
}

// IsElevated reports whether the current process runs with admin rights.
func IsElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}
