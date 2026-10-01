package handle

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/cookieguard/internal/risk"
	"github.com/cookieguard/internal/browser"

	"golang.org/x/sys/windows"
)

// SYSTEM_HANDLE_INFORMATION_EX is the structure used for NtQuerySystemInformation
// with SystemExtendedHandleInformation
// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_system_handle_information_ex
// We use this to enumerate all handles in the system.
type SYSTEM_HANDLE_INFORMATION_EX struct {
	ProcessID      uint32
	Handle         uint32
	ObjectTypeIndex  uint32
	HandleAttributes uint32
	GrantedAccess    uint32
	ObjectName     *uint16
	ObjectNameLength uint32
}

// Scan finds processes accessing a file
func Scan(filePath string) ([]risk.ProcessInfo, error) {
	// Get kernel path of the file (to match system handle paths)
	kernelPath, err := getKernelPath(filePath)
	if err != nil {
		return nil, err
	}

	// Query all system handles
	handles, err := querySystemHandles()
	if err != nil {
		return nil, err
	}

	var processes []risk.ProcessInfo
	for _, h := range handles {
		if h.ObjectName == nil || h.ObjectNameLength == 0 {
			continue
		}

		// Convert ObjectName to string
		objectName := syscall.UTF16ToString((*[1 << 30]uint16)(unsafe.Pointer(h.ObjectName))[:h.ObjectNameLength/2])

		// Check if this handle points to our cookie file
		if strings.EqualFold(objectName, kernelPath) {
			// Get process info for this handle
			proc, err := getProcessInfo(h.ProcessID)
			if err != nil {
				continue
			}

			// Mark as browser if process name matches
			proc.IsBrowser = browser.IsBrowserProcess(proc.Name)

			processes = append(processes, proc)
		}
	}

	return processes, nil
}

// getKernelPath returns the canonical kernel path for a file
func getKernelPath(filePath string) (string, error) {
	// Open the file to get its kernel path
	handle, err := windows.CreateFile(
		windows.StringToUTF16Ptr(filePath),
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)

	// Get the file's volume path
	var volumeName [256]uint16
	if err := windows.GetVolumePathName(windows.StringToUTF16Ptr(filePath), &volumeName[0], uint32(len(volumeName))); err != nil {
		return "", err
	}
	volumePath := windows.UTF16ToString(volumeName[:])

	// Get the full path from the handle
	var finalPath [256]uint16
	if _, err := windows.GetFinalPathNameByHandle(handle, &finalPath[0], uint32(len(finalPath)), windows.FILE_NAME_NORMALIZED); err != nil {
		return "", err
	}

	// Convert to UTF16 string
	return windows.UTF16ToString(finalPath[:]), nil
}

// querySystemHandles queries all system handles
func querySystemHandles() ([]SYSTEM_HANDLE_INFORMATION_EX, error) {
	var ( 
		buf []byte
		size uint32
	)

	// First call to get required buffer size
	err := windows.NtQuerySystemInformation(
		windows.SystemExtendedHandleInformation,
		nil,
		0,
		&size,
	)
	if err != nil {
		return nil, err
	}

	// Allocate buffer
	buf = make([]byte, size)
	err = windows.NtQuerySystemInformation(
		windows.SystemExtendedHandleInformation,
		&buf[0],
		size,
		&size,
	)
	if err != nil {
		return nil, err
	}

	// Parse the buffer
	var handles []SYSTEM_HANDLE_INFORMATION_EX
	ptr := (*[1 << 30]byte)(unsafe.Pointer(&buf[0]))
	for i := 0; i < int(size); i += 24 { // 24 = size of SYSTEM_HANDLE_INFORMATION_EX
		h := (*SYSTEM_HANDLE_INFORMATION_EX)(unsafe.Pointer(&ptr[i]))
		handles = append(handles, *h)
	}

	return handles, nil
}

// getProcessInfo retrieves process name and path
func getProcessInfo(pid uint32) (risk.ProcessInfo, error) {
	// Open process with required access
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return risk.ProcessInfo{}, err
	}
	defer windows.CloseHandle(h)

	// Get process path
	var path [256]uint16
	if _, err := windows.GetModuleFileNameEx(h, 0, &path[0], uint32(len(path))); err != nil {
		return risk.ProcessInfo{}, err
	}

	// Get process name (without path)
	name := strings.ToLower(filepath.Base(windows.UTF16ToString(path[:])))

	return risk.ProcessInfo{
		PID: int(pid),
		Name: name,
		Path: windows.UTF16ToString(path[:]),
	}, nil
}