// Package watcher observes readable handles: filesystem change events cannot
// observe file reads on Windows.
package watcher

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cookieguard/internal/handle"
	"github.com/cookieguard/internal/risk"
)

type Event struct {
	Time time.Time `json:"time"`
	Kind string    `json:"kind"`
	handle.Observation
}

type Watcher struct {
	Interval        time.Duration
	Discover        func() ([]string, error)
	Emit            func(Event) error
	Status          func(handle.Report)
	IncludeBrowsers bool
	scan            func([]string) (handle.Report, error)
}

func eventKey(e Event) string {
	return fmt.Sprintf("%d:%d:%s:%s:%s", e.Process.PID, e.Process.StartTime, e.Process.Path, e.File, e.Kind)
}

// Run stops on cancellation and rediscovers files on every scan.
func (w *Watcher) Run(ctx context.Context) error {
	if w.Interval < 100*time.Millisecond {
		return errors.New("scan interval must be at least 100ms")
	}
	if w.Discover == nil || w.Emit == nil {
		return errors.New("missing discover or emit callback")
	}
	var scanner handle.Scanner
	scan := w.scan
	if scan == nil {
		scan = scanner.Scan
	}
	previous := make(map[string]bool)
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		paths, err := w.Discover()
		if err != nil {
			return err
		}
		report, err := scan(paths)
		if err != nil {
			return err
		}
		if w.Status != nil {
			w.Status(report)
		}
		current := make(map[string]bool)
		allowed, checked := make(map[int]bool), make(map[int]bool)
		for _, observation := range report.Observations {
			p := observation.Process
			if !checked[p.PID] {
				allowed[p.PID] = risk.IsAllowed(p)
				checked[p.PID] = true
			}
			kind := "review_access"
			if allowed[p.PID] {
				kind = "browser_access"
				if !w.IncludeBrowsers {
					continue
				}
			}
			event := Event{Time: time.Now().UTC(), Kind: kind, Observation: observation}
			key := eventKey(event)
			if current[key] {
				continue
			}
			current[key] = true
			if !previous[key] {
				if err := w.Emit(event); err != nil {
					return err
				}
			}
		}
		previous = current
		timer := time.NewTimer(w.Interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}
