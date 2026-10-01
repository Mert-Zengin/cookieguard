package watcher

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/cookieguard/internal/handle"
	"github.com/cookieguard/internal/risk"
	"github.com/cookieguard/internal/notify"
)

// Watcher monitors browser cookie files
type Watcher struct {
	watcher *fsnotify.Watcher
	paths   []string
	ctx     context.Context

// isDevToolsAbuse checks for Chrome DevTools Protocol abuse
func isDevToolsAbuse(pid int) bool {
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid), "get", "CommandLine")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	cmdLine := strings.ToLower(string(output))
	return strings.Contains(cmdLine, "--remote-debugging-port") || 
		strings.Contains(cmdLine, ":9222")
}

// isMemoryScraping detects direct browser memory access
func isMemoryScraping(pid int) bool {
	handles, err := handle.GetProcessHandles(pid)
	if err != nil {
		return false
	}
	for _, h := range handles {
		if h.ObjectType == "Process" && 
			(h.GrantedAccess&0x0008 != 0) { // PROCESS_VM_READ
			if handle.IsBrowserProcess(h.TargetPID) {
				return true
			}
		}
	}
	return false
}

}

// New creates a new Watcher
func New(paths []string) *Watcher {
	return &Watcher{
		paths: paths,
	
// isDevToolsAbuse checks for Chrome DevTools Protocol abuse
func isDevToolsAbuse(pid int) bool {
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid), "get", "CommandLine")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	cmdLine := strings.ToLower(string(output))
	return strings.Contains(cmdLine, "--remote-debugging-port") || 
		strings.Contains(cmdLine, ":9222")
}

// isMemoryScraping detects direct browser memory access
func isMemoryScraping(pid int) bool {
	handles, err := handle.GetProcessHandles(pid)
	if err != nil {
		return false
	}
	for _, h := range handles {
		if h.ObjectType == "Process" && 
			(h.GrantedAccess&0x0008 != 0) { // PROCESS_VM_READ
			if handle.IsBrowserProcess(h.TargetPID) {
				return true
			}
		}
	}
	return false
}

}

}

// Start begins monitoring
func (w *Watcher) Start() error {
	ctx, cancel := context.WithCancel(context.Background())
	w.ctx = ctx

	// Create watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	
// isDevToolsAbuse checks for Chrome DevTools Protocol abuse
func isDevToolsAbuse(pid int) bool {
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid), "get", "CommandLine")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	cmdLine := strings.ToLower(string(output))
	return strings.Contains(cmdLine, "--remote-debugging-port") || 
		strings.Contains(cmdLine, ":9222")
}

// isMemoryScraping detects direct browser memory access
func isMemoryScraping(pid int) bool {
	handles, err := handle.GetProcessHandles(pid)
	if err != nil {
		return false
	}
	for _, h := range handles {
		if h.ObjectType == "Process" && 
			(h.GrantedAccess&0x0008 != 0) { // PROCESS_VM_READ
			if handle.IsBrowserProcess(h.TargetPID) {
				return true
			}
		}
	}
	return false
}

}
	w.watcher = watcher

	// Add all paths
	for _, path := range w.paths {
		pathDir := filepath.Dir(path)
		if err := w.watcher.Add(pathDir); err != nil {
			return err
		
// isDevToolsAbuse checks for Chrome DevTools Protocol abuse
func isDevToolsAbuse(pid int) bool {
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid), "get", "CommandLine")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	cmdLine := strings.ToLower(string(output))
	return strings.Contains(cmdLine, "--remote-debugging-port") || 
		strings.Contains(cmdLine, ":9222")
}

// isMemoryScraping detects direct browser memory access
func isMemoryScraping(pid int) bool {
	handles, err := handle.GetProcessHandles(pid)
	if err != nil {
		return false
	}
	for _, h := range handles {
		if h.ObjectType == "Process" && 
			(h.GrantedAccess&0x0008 != 0) { // PROCESS_VM_READ
			if handle.IsBrowserProcess(h.TargetPID) {
				return true
			}
		}
	}
	return false
}

}
	
// isDevToolsAbuse checks for Chrome DevTools Protocol abuse
func isDevToolsAbuse(pid int) bool {
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid), "get", "CommandLine")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	cmdLine := strings.ToLower(string(output))
	return strings.Contains(cmdLine, "--remote-debugging-port") || 
		strings.Contains(cmdLine, ":9222")
}

// isMemoryScraping detects direct browser memory access
func isMemoryScraping(pid int) bool {
	handles, err := handle.GetProcessHandles(pid)
	if err != nil {
		return false
	}
	for _, h := range handles {
		if h.ObjectType == "Process" && 
			(h.GrantedAccess&0x0008 != 0) { // PROCESS_VM_READ
			if handle.IsBrowserProcess(h.TargetPID) {
				return true
			}
		}
	}
	return false
}

}

	// Start event loop
	go func() {
		for {
			select {
			case event, ok := <-w.watcher.Events:
				if !ok {
					return
				
// isDevToolsAbuse checks for Chrome DevTools Protocol abuse
func isDevToolsAbuse(pid int) bool {
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid), "get", "CommandLine")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	cmdLine := strings.ToLower(string(output))
	return strings.Contains(cmdLine, "--remote-debugging-port") || 
		strings.Contains(cmdLine, ":9222")
}

// isMemoryScraping detects direct browser memory access
func isMemoryScraping(pid int) bool {
	handles, err := handle.GetProcessHandles(pid)
	if err != nil {
		return false
	}
	for _, h := range handles {
		if h.ObjectType == "Process" && 
			(h.GrantedAccess&0x0008 != 0) { // PROCESS_VM_READ
			if handle.IsBrowserProcess(h.TargetPID) {
				return true
			}
		}
	}
	return false
}

}
				if event.Op&fsnotify.Write == fsnotify.Write {
					// Get accessing process PID
					pid, err := handle.GetPIDFromPath(event.Name)
					if err != nil {
						continue
					
// isDevToolsAbuse checks for Chrome DevTools Protocol abuse
func isDevToolsAbuse(pid int) bool {
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid), "get", "CommandLine")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	cmdLine := strings.ToLower(string(output))
	return strings.Contains(cmdLine, "--remote-debugging-port") || 
		strings.Contains(cmdLine, ":9222")
}

// isMemoryScraping detects direct browser memory access
func isMemoryScraping(pid int) bool {
	handles, err := handle.GetProcessHandles(pid)
	if err != nil {
		return false
	}
	for _, h := range handles {
		if h.ObjectType == "Process" && 
			(h.GrantedAccess&0x0008 != 0) { // PROCESS_VM_READ
			if handle.IsBrowserProcess(h.TargetPID) {
				return true
			}
		}
	}
	return false
}

}

					// Check for DevTools Protocol abuse
					if isDevToolsAbuse(pid) {
						notify.Alert(pid, "DevTools Protocol abuse detected")
					
// isDevToolsAbuse checks for Chrome DevTools Protocol abuse
func isDevToolsAbuse(pid int) bool {
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid), "get", "CommandLine")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	cmdLine := strings.ToLower(string(output))
	return strings.Contains(cmdLine, "--remote-debugging-port") || 
		strings.Contains(cmdLine, ":9222")
}

// isMemoryScraping detects direct browser memory access
func isMemoryScraping(pid int) bool {
	handles, err := handle.GetProcessHandles(pid)
	if err != nil {
		return false
	}
	for _, h := range handles {
		if h.ObjectType == "Process" && 
			(h.GrantedAccess&0x0008 != 0) { // PROCESS_VM_READ
			if handle.IsBrowserProcess(h.TargetPID) {
				return true
			}
		}
	}
	return false
}

}

					// Check for memory scraping attempts
					if isMemoryScraping(pid) {
						notify.Alert(pid, "Memory scraping detected")
					
// isDevToolsAbuse checks for Chrome DevTools Protocol abuse
func isDevToolsAbuse(pid int) bool {
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid), "get", "CommandLine")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	cmdLine := strings.ToLower(string(output))
	return strings.Contains(cmdLine, "--remote-debugging-port") || 
		strings.Contains(cmdLine, ":9222")
}

// isMemoryScraping detects direct browser memory access
func isMemoryScraping(pid int) bool {
	handles, err := handle.GetProcessHandles(pid)
	if err != nil {
		return false
	}
	for _, h := range handles {
		if h.ObjectType == "Process" && 
			(h.GrantedAccess&0x0008 != 0) { // PROCESS_VM_READ
			if handle.IsBrowserProcess(h.TargetPID) {
				return true
			}
		}
	}
	return false
}

}

					// Existing risk assessment
					if risk.IsHigh(pid) {
						notify.Alert(pid)
					
// isDevToolsAbuse checks for Chrome DevTools Protocol abuse
func isDevToolsAbuse(pid int) bool {
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid), "get", "CommandLine")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	cmdLine := strings.ToLower(string(output))
	return strings.Contains(cmdLine, "--remote-debugging-port") || 
		strings.Contains(cmdLine, ":9222")
}

// isMemoryScraping detects direct browser memory access
func isMemoryScraping(pid int) bool {
	handles, err := handle.GetProcessHandles(pid)
	if err != nil {
		return false
	}
	for _, h := range handles {
		if h.ObjectType == "Process" && 
			(h.GrantedAccess&0x0008 != 0) { // PROCESS_VM_READ
			if handle.IsBrowserProcess(h.TargetPID) {
				return true
			}
		}
	}
	return false
}

}
				
// isDevToolsAbuse checks for Chrome DevTools Protocol abuse
func isDevToolsAbuse(pid int) bool {
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid), "get", "CommandLine")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	cmdLine := strings.ToLower(string(output))
	return strings.Contains(cmdLine, "--remote-debugging-port") || 
		strings.Contains(cmdLine, ":9222")
}

// isMemoryScraping detects direct browser memory access
func isMemoryScraping(pid int) bool {
	handles, err := handle.GetProcessHandles(pid)
	if err != nil {
		return false
	}
	for _, h := range handles {
		if h.ObjectType == "Process" && 
			(h.GrantedAccess&0x0008 != 0) { // PROCESS_VM_READ
			if handle.IsBrowserProcess(h.TargetPID) {
				return true
			}
		}
	}
	return false
}

}
			case event, ok := <-w.watcher.Events:
				if !ok {
					return
				
// isDevToolsAbuse checks for Chrome DevTools Protocol abuse
func isDevToolsAbuse(pid int) bool {
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid), "get", "CommandLine")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	cmdLine := strings.ToLower(string(output))
	return strings.Contains(cmdLine, "--remote-debugging-port") || 
		strings.Contains(cmdLine, ":9222")
}

// isMemoryScraping detects direct browser memory access
func isMemoryScraping(pid int) bool {
	handles, err := handle.GetProcessHandles(pid)
	if err != nil {
		return false
	}
	for _, h := range handles {
		if h.ObjectType == "Process" && 
			(h.GrantedAccess&0x0008 != 0) { // PROCESS_VM_READ
			if handle.IsBrowserProcess(h.TargetPID) {
				return true
			}
		}
	}
	return false
}

}

				// Only process READ events
				if event.Op&fsnotify.Read == 0 {
					continue
				
// isDevToolsAbuse checks for Chrome DevTools Protocol abuse
func isDevToolsAbuse(pid int) bool {
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid), "get", "CommandLine")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	cmdLine := strings.ToLower(string(output))
	return strings.Contains(cmdLine, "--remote-debugging-port") || 
		strings.Contains(cmdLine, ":9222")
}

// isMemoryScraping detects direct browser memory access
func isMemoryScraping(pid int) bool {
	handles, err := handle.GetProcessHandles(pid)
	if err != nil {
		return false
	}
	for _, h := range handles {
		if h.ObjectType == "Process" && 
			(h.GrantedAccess&0x0008 != 0) { // PROCESS_VM_READ
			if handle.IsBrowserProcess(h.TargetPID) {
				return true
			}
		}
	}
	return false
}

}

				// Check if it's a cookie file
				if !strings.Contains(event.Name, "Cookies") && !strings.Contains(event.Name, "cookies") {
					continue
				
// isDevToolsAbuse checks for Chrome DevTools Protocol abuse
func isDevToolsAbuse(pid int) bool {
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid), "get", "CommandLine")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	cmdLine := strings.ToLower(string(output))
	return strings.Contains(cmdLine, "--remote-debugging-port") || 
		strings.Contains(cmdLine, ":9222")
}

// isMemoryScraping detects direct browser memory access
func isMemoryScraping(pid int) bool {
	handles, err := handle.GetProcessHandles(pid)
	if err != nil {
		return false
	}
	for _, h := range handles {
		if h.ObjectType == "Process" && 
			(h.GrantedAccess&0x0008 != 0) { // PROCESS_VM_READ
			if handle.IsBrowserProcess(h.TargetPID) {
				return true
			}
		}
	}
	return false
}

}

				// Scan for process accessing file
				processes, err := handle.Scan(event.Name)
				if err != nil {
					notify.Error("Scan error: %v", err)
					continue
				
// isDevToolsAbuse checks for Chrome DevTools Protocol abuse
func isDevToolsAbuse(pid int) bool {
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid), "get", "CommandLine")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	cmdLine := strings.ToLower(string(output))
	return strings.Contains(cmdLine, "--remote-debugging-port") || 
		strings.Contains(cmdLine, ":9222")
}

// isMemoryScraping detects direct browser memory access
func isMemoryScraping(pid int) bool {
	handles, err := handle.GetProcessHandles(pid)
	if err != nil {
		return false
	}
	for _, h := range handles {
		if h.ObjectType == "Process" && 
			(h.GrantedAccess&0x0008 != 0) { // PROCESS_VM_READ
			if handle.IsBrowserProcess(h.TargetPID) {
				return true
			}
		}
	}
	return false
}

}

				// Check risk
				for _, p := range processes {
					if !risk.IsAllowed(p) {
						notify.Alert("Suspicious access: %s (PID: %d)", p.Name, p.PID)
					
// isDevToolsAbuse checks for Chrome DevTools Protocol abuse
func isDevToolsAbuse(pid int) bool {
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid), "get", "CommandLine")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	cmdLine := strings.ToLower(string(output))
	return strings.Contains(cmdLine, "--remote-debugging-port") || 
		strings.Contains(cmdLine, ":9222")
}

// isMemoryScraping detects direct browser memory access
func isMemoryScraping(pid int) bool {
	handles, err := handle.GetProcessHandles(pid)
	if err != nil {
		return false
	}
	for _, h := range handles {
		if h.ObjectType == "Process" && 
			(h.GrantedAccess&0x0008 != 0) { // PROCESS_VM_READ
			if handle.IsBrowserProcess(h.TargetPID) {
				return true
			}
		}
	}
	return false
}

}
				
// isDevToolsAbuse checks for Chrome DevTools Protocol abuse
func isDevToolsAbuse(pid int) bool {
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid), "get", "CommandLine")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	cmdLine := strings.ToLower(string(output))
	return strings.Contains(cmdLine, "--remote-debugging-port") || 
		strings.Contains(cmdLine, ":9222")
}

// isMemoryScraping detects direct browser memory access
func isMemoryScraping(pid int) bool {
	handles, err := handle.GetProcessHandles(pid)
	if err != nil {
		return false
	}
	for _, h := range handles {
		if h.ObjectType == "Process" && 
			(h.GrantedAccess&0x0008 != 0) { // PROCESS_VM_READ
			if handle.IsBrowserProcess(h.TargetPID) {
				return true
			}
		}
	}
	return false
}

}

			case err, ok := <-w.watcher.Errors:
				if !ok {
					return
				
// isDevToolsAbuse checks for Chrome DevTools Protocol abuse
func isDevToolsAbuse(pid int) bool {
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid), "get", "CommandLine")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	cmdLine := strings.ToLower(string(output))
	return strings.Contains(cmdLine, "--remote-debugging-port") || 
		strings.Contains(cmdLine, ":9222")
}

// isMemoryScraping detects direct browser memory access
func isMemoryScraping(pid int) bool {
	handles, err := handle.GetProcessHandles(pid)
	if err != nil {
		return false
	}
	for _, h := range handles {
		if h.ObjectType == "Process" && 
			(h.GrantedAccess&0x0008 != 0) { // PROCESS_VM_READ
			if handle.IsBrowserProcess(h.TargetPID) {
				return true
			}
		}
	}
	return false
}

}
				notify.Error("Watcher error: %v", err)
			
// isDevToolsAbuse checks for Chrome DevTools Protocol abuse
func isDevToolsAbuse(pid int) bool {
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid), "get", "CommandLine")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	cmdLine := strings.ToLower(string(output))
	return strings.Contains(cmdLine, "--remote-debugging-port") || 
		strings.Contains(cmdLine, ":9222")
}

// isMemoryScraping detects direct browser memory access
func isMemoryScraping(pid int) bool {
	handles, err := handle.GetProcessHandles(pid)
	if err != nil {
		return false
	}
	for _, h := range handles {
		if h.ObjectType == "Process" && 
			(h.GrantedAccess&0x0008 != 0) { // PROCESS_VM_READ
			if handle.IsBrowserProcess(h.TargetPID) {
				return true
			}
		}
	}
	return false
}

}
		
// isDevToolsAbuse checks for Chrome DevTools Protocol abuse
func isDevToolsAbuse(pid int) bool {
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid), "get", "CommandLine")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	cmdLine := strings.ToLower(string(output))
	return strings.Contains(cmdLine, "--remote-debugging-port") || 
		strings.Contains(cmdLine, ":9222")
}

// isMemoryScraping detects direct browser memory access
func isMemoryScraping(pid int) bool {
	handles, err := handle.GetProcessHandles(pid)
	if err != nil {
		return false
	}
	for _, h := range handles {
		if h.ObjectType == "Process" && 
			(h.GrantedAccess&0x0008 != 0) { // PROCESS_VM_READ
			if handle.IsBrowserProcess(h.TargetPID) {
				return true
			}
		}
	}
	return false
}

}
		
// isDevToolsAbuse checks for Chrome DevTools Protocol abuse
func isDevToolsAbuse(pid int) bool {
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid), "get", "CommandLine")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	cmdLine := strings.ToLower(string(output))
	return strings.Contains(cmdLine, "--remote-debugging-port") || 
		strings.Contains(cmdLine, ":9222")
}

// isMemoryScraping detects direct browser memory access
func isMemoryScraping(pid int) bool {
	handles, err := handle.GetProcessHandles(pid)
	if err != nil {
		return false
	}
	for _, h := range handles {
		if h.ObjectType == "Process" && 
			(h.GrantedAccess&0x0008 != 0) { // PROCESS_VM_READ
			if handle.IsBrowserProcess(h.TargetPID) {
				return true
			}
		}
	}
	return false
}

}()

	return nil

// isDevToolsAbuse checks for Chrome DevTools Protocol abuse
func isDevToolsAbuse(pid int) bool {
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid), "get", "CommandLine")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	cmdLine := strings.ToLower(string(output))
	return strings.Contains(cmdLine, "--remote-debugging-port") || 
		strings.Contains(cmdLine, ":9222")
}

// isMemoryScraping detects direct browser memory access
func isMemoryScraping(pid int) bool {
	handles, err := handle.GetProcessHandles(pid)
	if err != nil {
		return false
	}
	for _, h := range handles {
		if h.ObjectType == "Process" && 
			(h.GrantedAccess&0x0008 != 0) { // PROCESS_VM_READ
			if handle.IsBrowserProcess(h.TargetPID) {
				return true
			}
		}
	}
	return false
}

}

// Stop terminates the watcher
func (w *Watcher) Stop() error {
	if w.watcher == nil {
		return errors.New("watcher not started")
	
// isDevToolsAbuse checks for Chrome DevTools Protocol abuse
func isDevToolsAbuse(pid int) bool {
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid), "get", "CommandLine")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	cmdLine := strings.ToLower(string(output))
	return strings.Contains(cmdLine, "--remote-debugging-port") || 
		strings.Contains(cmdLine, ":9222")
}

// isMemoryScraping detects direct browser memory access
func isMemoryScraping(pid int) bool {
	handles, err := handle.GetProcessHandles(pid)
	if err != nil {
		return false
	}
	for _, h := range handles {
		if h.ObjectType == "Process" && 
			(h.GrantedAccess&0x0008 != 0) { // PROCESS_VM_READ
			if handle.IsBrowserProcess(h.TargetPID) {
				return true
			}
		}
	}
	return false
}

}
	return w.watcher.Close()

// isDevToolsAbuse checks for Chrome DevTools Protocol abuse
func isDevToolsAbuse(pid int) bool {
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid), "get", "CommandLine")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	cmdLine := strings.ToLower(string(output))
	return strings.Contains(cmdLine, "--remote-debugging-port") || 
		strings.Contains(cmdLine, ":9222")
}

// isMemoryScraping detects direct browser memory access
func isMemoryScraping(pid int) bool {
	handles, err := handle.GetProcessHandles(pid)
	if err != nil {
		return false
	}
	for _, h := range handles {
		if h.ObjectType == "Process" && 
			(h.GrantedAccess&0x0008 != 0) { // PROCESS_VM_READ
			if handle.IsBrowserProcess(h.TargetPID) {
				return true
			}
		}
	}
	return false
}

}