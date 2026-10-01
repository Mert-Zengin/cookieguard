// Package handle observes open Windows handles without reading file contents.
package handle

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"github.com/cookieguard/internal/risk"
	"golang.org/x/sys/windows"
)

const maxBuffer = 64 << 20

type entry struct {
	pid, value uintptr
	access     uint32
	typeIndex  uint16
}

type FileID struct{ Volume, High, Low uint32 }

// Observation proves only that a process held a readable handle at scan time.
// It does not prove that the process read the file or that it is malicious.
type Observation struct {
	Process risk.ProcessInfo `json:"process"`
	File    string           `json:"file"`
	Access  uint32           `json:"access"`
}

type Report struct {
	DurationMS            int64         `json:"duration_ms"`
	TargetsRequested      int           `json:"targets_requested"`
	TargetsAvailable      int           `json:"targets_available"`
	Observations          []Observation `json:"observations"`
	Handles               int           `json:"handles"`
	Checked               int           `json:"checked"`
	InaccessibleProcesses int           `json:"inaccessible_processes"`
	UnresolvedHandles     int           `json:"unresolved_handles"`
	UnavailableTargets    []string      `json:"unavailable_targets,omitempty"`
}

// Scanner reuses its query buffer. Use it from only one goroutine.
type Scanner struct{ buf []byte }

func fileID(h windows.Handle) (FileID, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return FileID{}, err
	}
	if info.FileIndexHigh == 0 && info.FileIndexLow == 0 {
		return FileID{}, errors.New("filesystem does not provide a usable file identity")
	}
	return FileID{info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow}, nil
}

func parseTable(buf []byte, pointerSize int) ([]entry, error) {
	if pointerSize != 4 && pointerSize != 8 {
		return nil, errors.New("unsupported pointer size")
	}
	header, stride := 2*pointerSize, 3*pointerSize+16
	if len(buf) < header {
		return nil, errors.New("truncated handle table header")
	}
	readPtr := func(b []byte) uintptr {
		if pointerSize == 8 {
			return uintptr(binary.LittleEndian.Uint64(b))
		}
		return uintptr(binary.LittleEndian.Uint32(b))
	}
	count := readPtr(buf)
	if count > uintptr((len(buf)-header)/stride) {
		return nil, errors.New("truncated handle table entries")
	}
	out := make([]entry, int(count))
	for i := range out {
		b := buf[header+i*stride : header+(i+1)*stride]
		out[i] = entry{pid: readPtr(b[pointerSize:]), value: readPtr(b[2*pointerSize:]),
			access:    binary.LittleEndian.Uint32(b[3*pointerSize:]),
			typeIndex: binary.LittleEndian.Uint16(b[3*pointerSize+6:])}
	}
	return out, nil
}

func (s *Scanner) table() ([]entry, error) {
	if len(s.buf) == 0 {
		s.buf = make([]byte, 1<<20)
	}
	for range 10 {
		var needed uint32
		err := windows.NtQuerySystemInformation(windows.SystemExtendedHandleInformation,
			unsafe.Pointer(&s.buf[0]), uint32(len(s.buf)), &needed)
		if err == nil {
			if needed == 0 || int(needed) > len(s.buf) {
				return nil, errors.New("invalid handle table size")
			}
			return parseTable(s.buf[:needed], int(unsafe.Sizeof(uintptr(0))))
		}
		if !errors.Is(err, windows.STATUS_INFO_LENGTH_MISMATCH) && !errors.Is(err, windows.STATUS_BUFFER_TOO_SMALL) {
			return nil, err
		}
		size := max(len(s.buf)*2, int(needed)+65536)
		if size > maxBuffer {
			return nil, errors.New("handle table exceeds 64 MiB safety limit")
		}
		s.buf = make([]byte, size)
	}
	return nil, errors.New("handle table changed too quickly; retry next scan")
}

// Scan counts coverage gaps explicitly. No observations is not a clean bill
// of health. Targets are reopened each time to handle database replacement.
func (s *Scanner) Scan(paths []string) (report Report, scanErr error) {
	start := time.Now()
	defer func() { report.DurationMS = time.Since(start).Milliseconds() }()
	report.TargetsRequested = len(paths)
	targets := make(map[FileID]string)
	var refs []windows.Handle
	defer func() {
		for _, h := range refs {
			windows.CloseHandle(h)
		}
	}()
	for _, path := range paths {
		p, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return report, err
		}
		h, err := windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
			nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			report.UnavailableTargets = append(report.UnavailableTargets, path)
			continue
		}
		refs = append(refs, h)
		id, err := fileID(h)
		if err != nil {
			report.UnavailableTargets = append(report.UnavailableTargets, path)
			continue
		}
		targets[id] = path
	}
	report.TargetsAvailable = len(targets)
	if len(targets) == 0 {
		return report, nil
	}
	entries, err := s.table()
	if err != nil {
		return report, err
	}
	report.Handles = len(entries)
	ownPID := uintptr(os.Getpid())
	var fileType uint16
	for _, e := range entries {
		if e.pid != ownPID {
			continue
		}
		for _, h := range refs {
			if e.value == uintptr(h) {
				fileType = e.typeIndex
				break
			}
		}
		if fileType != 0 {
			break
		}
	}
	if fileType == 0 {
		return report, errors.New("could not identify Windows file handle type")
	}
	opened := make(map[uintptr]windows.Handle)
	defer func() {
		for _, h := range opened {
			if h != 0 {
				windows.CloseHandle(h)
			}
		}
	}()
	seen := make(map[string]bool)
	current := windows.CurrentProcess()
	for _, e := range entries {
		if e.pid == ownPID || e.pid <= 4 || e.pid > 0xffffffff || e.typeIndex != fileType || e.access&windows.FILE_READ_DATA == 0 {
			continue
		}
		ph, ok := opened[e.pid]
		if !ok {
			ph, err = windows.OpenProcess(windows.PROCESS_DUP_HANDLE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(e.pid))
			if err != nil {
				ph = 0
				report.InaccessibleProcesses++
			}
			opened[e.pid] = ph
		}
		if ph == 0 {
			continue
		}
		var duplicate windows.Handle
		// Never close or alter the source process's handle.
		if err := windows.DuplicateHandle(ph, windows.Handle(e.value), current, &duplicate, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
			report.UnresolvedHandles++
			continue
		}
		kind, typeErr := windows.GetFileType(duplicate)
		var id FileID
		var idErr error
		if typeErr == nil && kind == windows.FILE_TYPE_DISK {
			id, idErr = fileID(duplicate)
			report.Checked++
		}
		windows.CloseHandle(duplicate)
		if typeErr != nil || idErr != nil {
			report.UnresolvedHandles++
			continue
		}
		if kind != windows.FILE_TYPE_DISK {
			continue
		}
		path, match := targets[id]
		if !match {
			continue
		}
		key := fmt.Sprintf("%d:%s", e.pid, path)
		if seen[key] {
			continue
		}
		seen[key] = true
		var image [32768]uint16
		n := uint32(len(image))
		imagePath := ""
		if windows.QueryFullProcessImageName(ph, 0, &image[0], &n) == nil {
			imagePath = windows.UTF16ToString(image[:n])
		}
		var c, exit, k, u windows.Filetime
		var start int64
		if windows.GetProcessTimes(ph, &c, &exit, &k, &u) == nil {
			start = c.Nanoseconds()
		}
		report.Observations = append(report.Observations, Observation{
			Process: risk.ProcessInfo{PID: int(e.pid), Name: filepath.Base(imagePath), Path: imagePath, StartTime: start},
			File:    path, Access: e.access,
		})
	}
	return report, nil
}
