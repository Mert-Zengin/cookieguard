package notify

import (
	"context"
	"time"

	"golang.org/x/sys/windows"
)

type alert struct{ title, body string }

// Desktop bounds queued dialogs and rate-limits prompts. Notifications never
// block the handle scanner. At most one message box is open at a time.
type Desktop struct{ queue chan alert }

func NewDesktop(ctx context.Context) *Desktop {
	d := &Desktop{queue: make(chan alert, 1)}
	go func() {
		var last time.Time
		for {
			select {
			case <-ctx.Done():
				return
			case a := <-d.queue:
				if time.Since(last) < 30*time.Second {
					continue
				}
				body, err := windows.UTF16PtrFromString(a.body)
				if err != nil {
					continue
				}
				title, err := windows.UTF16PtrFromString(a.title)
				if err != nil {
					continue
				}
				last = time.Now()
				windows.MessageBox(0, body, title, windows.MB_OK|windows.MB_ICONWARNING)
			}
		}
	}()
	return d
}

func (d *Desktop) Show(title, body string) {
	select {
	case d.queue <- alert{title: title, body: body}:
	default:
	}
}
