// Package watcher observes readable handles: filesystem change events cannot
// observe file reads on Windows.
package watcher

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cookieguard/internal/handle"
	"github.com/cookieguard/internal/risk"
	"github.com/cookieguard/internal/threat"
)

type Event struct {
	Time     time.Time       `json:"time"`
	Kind     string          `json:"kind"`
	Level    string          `json:"level"`
	Signals  []threat.Signal `json:"signals,omitempty"`
	Families []string        `json:"associated_families,omitempty"`
	handle.Observation
}

type Watcher struct {
	Interval        time.Duration
	Discover        func() ([]string, error)
	Emit            func(Event) error
	Status          func(handle.Report)
	IncludeBrowsers bool
	Started         func() []risk.ProcessInfo
	scan            func([]string) (handle.Report, error)
}

func eventKey(e Event) string {
	ids := make([]string, 0, len(e.Signals))
	for _, s := range e.Signals {
		ids = append(ids, s.ID)
	}
	return fmt.Sprintf("%d:%d:%s:%s:%s:%s:%s", e.Process.PID, e.Process.StartTime, e.Process.Path, e.File, e.Kind, e.Level, strings.Join(ids, ","))
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
		assessed := make(map[int]threat.Assessment)
		for _, observation := range report.Observations {
			p := observation.Process
			assessment, ok := assessed[p.PID]
			if !ok {
				assessment = threat.Assess(p)
				assessed[p.PID] = assessment
			}
			kind := "review_access"
			if assessment.Level == "expected" {
				kind = "browser_access"
				if !w.IncludeBrowsers {
					continue
				}
			}
			event := Event{
				Time: time.Now().UTC(), Kind: kind, Level: assessment.Level,
				Signals: assessment.Signals, Families: assessment.Families,
				Observation: observation,
			}
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
		if w.Started != nil {
			for _, p := range w.Started() {
				assessment := threat.AssessProcess(p)
				if assessment.Level == "info" {
					continue
				}
				event := Event{
					Time: time.Now().UTC(), Kind: "process_started", Level: assessment.Level,
					Signals: assessment.Signals, Families: assessment.Families,
					Observation: handle.Observation{Process: p},
				}
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
