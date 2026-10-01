package watcher

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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
}

// New creates a new Watcher
func New(paths []string) *Watcher {
	return &Watcher{
		paths: paths,
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
	}
	w.watcher = watcher

	// Add all paths
	for _, path := range w.paths {
		pathDir := filepath.Dir(path)
		if err := w.watcher.Add(pathDir); err != nil {
			return err
		}
	}

	// Start event loop
	go func() {
		for {
			select {
			case event, ok := <-w.watcher.Events:
				if !ok {
					return
				}

				// Only process READ events
				if event.Op&fsnotify.Read == 0 {
					continue
				}

				// Check if it's a cookie file
				if !strings.Contains(event.Name, "Cookies") && !strings.Contains(event.Name, "cookies") {
					continue
				}

				// Scan for process accessing file
				processes, err := handle.Scan(event.Name)
				if err != nil {
					notify.Error("Scan error: %v", err)
					continue
				}

				// Check risk
				for _, p := range processes {
					if !risk.IsAllowed(p) {
						notify.Alert("Suspicious access: %s (PID: %d)", p.Name, p.PID)
					}
				}

			case err, ok := <-w.watcher.Errors:
				if !ok {
					return
				}
				notify.Error("Watcher error: %v", err)
			}
		}
		}()

	return nil
}

// Stop terminates the watcher
func (w *Watcher) Stop() error {
	if w.watcher == nil {
		return errors.New("watcher not started")
	}
	return w.watcher.Close()
}