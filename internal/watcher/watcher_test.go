package watcher

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cookieguard/internal/handle"
	"github.com/cookieguard/internal/risk"
)

func TestKeyIncludesProcessIdentity(t *testing.T) {
	a := Event{Kind: "review_access", Observation: handle.Observation{File: "fixture", Process: risk.ProcessInfo{PID: 10, StartTime: 20, Path: "process"}}}
	b := a
	b.Process.StartTime++
	if eventKey(a) == eventKey(b) {
		t.Fatal("reused PID was deduplicated")
	}
	b = a
	b.File = "other"
	if eventKey(a) == eventKey(b) {
		t.Fatal("different file was deduplicated")
	}
}

func TestDedupAndReappearance(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scans, events := 0, 0
	observation := handle.Observation{File: "synthetic", Process: risk.ProcessInfo{PID: 99, Path: "untrusted-fixture", StartTime: 123}}
	w := Watcher{
		Interval: 100 * time.Millisecond,
		Discover: func() ([]string, error) { return []string{"synthetic"}, nil },
		scan: func([]string) (handle.Report, error) {
			scans++
			if scans > 4 {
				t.Fatal("did not cancel")
			}
			if scans == 3 {
				return handle.Report{}, nil
			}
			return handle.Report{Observations: []handle.Observation{observation, observation}}, nil
		},
		Emit: func(e Event) error {
			if e.Kind != "review_access" {
				t.Fatalf("unexpected kind %s", e.Kind)
			}
			events++
			if events == 2 {
				cancel()
			}
			return nil
		},
	}
	if err := w.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if scans != 4 || events != 2 {
		t.Fatalf("scans=%d events=%d", scans, events)
	}
}

func TestEmitAndScanErrorsPropagate(t *testing.T) {
	failure := errors.New("fixture error")
	w := Watcher{Interval: time.Second, Discover: func() ([]string, error) { return nil, nil }, Emit: func(Event) error { return failure }}
	w.scan = func([]string) (handle.Report, error) { return handle.Report{}, failure }
	if !errors.Is(w.Run(context.Background()), failure) {
		t.Fatal("scan error swallowed")
	}
	w.scan = func([]string) (handle.Report, error) {
		return handle.Report{Observations: []handle.Observation{{Process: risk.ProcessInfo{PID: 99}, File: "fixture"}}}, nil
	}
	if !errors.Is(w.Run(context.Background()), failure) {
		t.Fatal("emit error swallowed")
	}
}

func TestRunValidationAndCancellation(t *testing.T) {
	w := Watcher{Interval: time.Second}
	if w.Run(context.Background()) == nil {
		t.Fatal("accepted missing callbacks")
	}
	w.Discover = func() ([]string, error) { return nil, nil }
	w.Emit = func(Event) error { return nil }
	w.Interval = 0
	if w.Run(context.Background()) == nil {
		t.Fatal("accepted busy-loop interval")
	}
	w.Interval = time.Second
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := w.Run(ctx); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("discover failed")
	w.Discover = func() ([]string, error) { return nil, failure }
	if !errors.Is(w.Run(context.Background()), failure) {
		t.Fatal("discovery error was swallowed")
	}
}
