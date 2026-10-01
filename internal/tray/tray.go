// Package tray shows a Windows notification-area (taskbar tray) icon so the
// user can see that CookieGuard is running and open its log or quit.
//
// It uses Shell_NotifyIcon with a message-only window. It is pure Go and does
// not require CGO.
package tray

import (
	"fmt"
	"os"
	"runtime"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	wmApp          = 0x8000
	wmCallback     = wmApp + 1
	wmCommand      = 0x0111
	wmDestroy      = 0x0002
	wmClose        = 0x0010
	wmLButtonUp    = 0x0202
	wmLButtonDbl   = 0x0203
	wmRButtonUp    = 0x0205
	wmContextMenu  = 0x007B
	nifMessage     = 0x00000001
	nifIcon        = 0x00000002
	nifTip         = 0x00000004
	nifInfo        = 0x00000010
	niifInfo       = 0x00000001
	nimAdd         = 0x00000000
	nimModify      = 0x00000001
	nimDelete      = 0x00000002
	imageIcon      = 1
	lrLoadFromFile = 0x00000010
	mfString       = 0x00000000
	mfSeparator    = 0x00000800
	tpmReturnCmd   = 0x0100
	tpmRightButton = 0x0002
	tpmBottomAlign = 0x0020
)

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procRegisterClassExW = user32.NewProc("RegisterClassExW")
	procCreateWindowExW  = user32.NewProc("CreateWindowExW")
	procDefWindowProcW   = user32.NewProc("DefWindowProcW")
	procDestroyWindow    = user32.NewProc("DestroyWindow")
	procGetMessageW      = user32.NewProc("GetMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procDispatchMessageW = user32.NewProc("DispatchMessageW")
	procPostQuitMessage  = user32.NewProc("PostQuitMessage")
	procCreatePopupMenu  = user32.NewProc("CreatePopupMenu")
	procDestroyMenu      = user32.NewProc("DestroyMenu")
	procAppendMenuW      = user32.NewProc("AppendMenuW")
	procTrackPopupMenu   = user32.NewProc("TrackPopupMenu")
	procSetForegroundWin = user32.NewProc("SetForegroundWindow")
	procGetCursorPos     = user32.NewProc("GetCursorPos")
	procPostMessageW     = user32.NewProc("PostMessageW")
	procLoadImageW       = user32.NewProc("LoadImageW")
	procDestroyIcon      = user32.NewProc("DestroyIcon")
	procUnregisterClassW = user32.NewProc("UnregisterClassW")
	procShellNotifyIconW = shell32.NewProc("Shell_NotifyIconW")
	procGetModuleHandleW = kernel32.NewProc("GetModuleHandleW")
)

type point struct{ X, Y int32 }

type msg struct {
	HWnd    windows.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
}

type wndClassEx struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     windows.Handle
	HIcon         windows.Handle
	HCursor       windows.Handle
	HbrBackground windows.Handle
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       windows.Handle
}

type notifyIconData struct {
	CbSize           uint32
	HWnd             windows.Handle
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            windows.Handle
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UVersion         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         windows.GUID
	HBalloonIcon     windows.Handle
}

// MenuItem is one entry in the tray context menu.
type MenuItem struct {
	ID        int
	Label     string
	Separator bool
}

// Options configures the tray icon.
type Options struct {
	Tooltip       string
	IconBytes     []byte // ICO file contents; written to a temp file for LoadImage
	Items         []MenuItem
	OnSelect      func(id int)
	OnDoubleClick func()
	Balloon       string
}

// Tray owns the notification-area icon and its message loop.
type Tray struct {
	hwnd   windows.Handle
	hicon  windows.Handle
	nid    notifyIconData
	opts   Options
	class  *uint16
	closed atomic.Bool
}

var active atomic.Pointer[Tray]

func wndProc(hwnd, message, wparam, lparam uintptr) uintptr {
	t := active.Load()
	switch uint32(message) {
	case wmCallback:
		if t == nil {
			break
		}
		switch uint32(lparam) & 0xffff {
		case wmLButtonDbl:
			if t.opts.OnDoubleClick != nil {
				go t.opts.OnDoubleClick()
			}
		case wmRButtonUp, wmContextMenu:
			t.showMenu()
		}
		return 0
	case wmCommand:
		if t != nil && t.opts.OnSelect != nil {
			go t.opts.OnSelect(int(uint16(wparam)))
		}
		return 0
	case wmClose:
		procDestroyWindow.Call(hwnd)
		return 0
	case wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	}
	ret, _, _ := procDefWindowProcW.Call(hwnd, message, wparam, lparam)
	return ret
}

// Start creates the icon and runs its message loop on a locked OS thread. It
// returns immediately; the loop keeps running until Close is called.
func Start(opts Options) (*Tray, error) {
	t := &Tray{opts: opts}
	if len(opts.IconBytes) > 0 {
		if h, err := loadIconFile(opts.IconBytes); err == nil {
			t.hicon = h
		}
	}
	hInstance, _, _ := procGetModuleHandleW.Call(0)

	className, err := windows.UTF16PtrFromString("CookieGuardTray")
	if err != nil {
		return nil, err
	}
	t.class = className
	wc := wndClassEx{
		CbSize:        uint32(unsafe.Sizeof(wndClassEx{})),
		LpfnWndProc:   windows.NewCallback(wndProc),
		HInstance:     windows.Handle(hInstance),
		LpszClassName: className,
	}
	if r, _, e := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		return nil, fmt.Errorf("RegisterClassEx: %w", e)
	}

	// HWND_MESSAGE = (HWND)-3 creates a message-only window.
	hwnd, _, e := procCreateWindowExW.Call(0, uintptr(unsafe.Pointer(className)), 0, 0, 0, 0, 0, 0, ^uintptr(2), 0, hInstance, 0)
	if hwnd == 0 {
		return nil, fmt.Errorf("CreateWindowEx: %w", e)
	}
	t.hwnd = windows.Handle(hwnd)

	t.nid = notifyIconData{
		HWnd:             t.hwnd,
		UID:              1,
		UFlags:           nifMessage | nifTip,
		UCallbackMessage: wmCallback,
	}
	copyUTF16(t.nid.SzTip[:], opts.Tooltip)
	if t.hicon != 0 {
		t.nid.UFlags |= nifIcon
		t.nid.HIcon = t.hicon
	}
	t.nid.CbSize = uint32(unsafe.Sizeof(t.nid))
	if err := t.notify(nimAdd); err != nil {
		procDestroyWindow.Call(hwnd)
		return nil, err
	}
	if opts.Balloon != "" {
		t.nid.UFlags = nifInfo
		t.nid.DwInfoFlags = niifInfo
		copyUTF16(t.nid.SzInfoTitle[:], "CookieGuard")
		copyUTF16(t.nid.SzInfo[:], opts.Balloon)
		_ = t.notify(nimModify)
		t.nid.UFlags = nifMessage | nifTip | nifIcon
	}
	active.Store(t)

	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		var m msg
		for {
			r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
			if int32(r) <= 0 {
				return
			}
			procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
			procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
		}
	}()
	return t, nil
}

func (t *Tray) notify(message uint32) error {
	r, _, e := procShellNotifyIconW.Call(uintptr(message), uintptr(unsafe.Pointer(&t.nid)))
	if r == 0 {
		return fmt.Errorf("Shell_NotifyIcon(%d): %w", message, e)
	}
	return nil
}

func (t *Tray) showMenu() {
	hmenu, _, _ := procCreatePopupMenu.Call()
	if hmenu == 0 {
		return
	}
	defer procDestroyMenu.Call(hmenu)
	for _, item := range t.opts.Items {
		if item.Separator {
			procAppendMenuW.Call(hmenu, mfSeparator, 0, 0)
			continue
		}
		label, err := windows.UTF16PtrFromString(item.Label)
		if err != nil {
			continue
		}
		procAppendMenuW.Call(hmenu, mfString, uintptr(item.ID), uintptr(unsafe.Pointer(label)))
	}
	var p point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&p)))
	procSetForegroundWin.Call(uintptr(t.hwnd))
	cmd, _, _ := procTrackPopupMenu.Call(hmenu, tpmReturnCmd|tpmRightButton|tpmBottomAlign, uintptr(p.X), uintptr(p.Y), 0, uintptr(t.hwnd), 0)
	if cmd != 0 && t.opts.OnSelect != nil {
		go t.opts.OnSelect(int(cmd))
	}
}

// Close removes the icon and stops the message loop.
func (t *Tray) Close() {
	if t == nil || !t.closed.CompareAndSwap(false, true) {
		return
	}
	t.notify(nimDelete)
	if t.hicon != 0 {
		procDestroyIcon.Call(uintptr(t.hicon))
	}
	if t.hwnd != 0 {
		procPostMessageW.Call(uintptr(t.hwnd), wmClose, 0, 0)
	}
	if t.class != nil {
		procUnregisterClassW.Call(uintptr(unsafe.Pointer(t.class)), 0)
	}
	active.Store(nil)
}

func loadIconFile(data []byte) (windows.Handle, error) {
	f, err := os.CreateTemp("", "cookieguard-*.ico")
	if err != nil {
		return 0, err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return 0, err
	}
	f.Close()
	path, err := windows.UTF16PtrFromString(f.Name())
	if err != nil {
		return 0, err
	}
	h, _, e := procLoadImageW.Call(0, uintptr(unsafe.Pointer(path)), imageIcon, 0, 0, lrLoadFromFile)
	if h == 0 {
		return 0, fmt.Errorf("LoadImage: %w", e)
	}
	return windows.Handle(h), nil
}

func copyUTF16(dst []uint16, s string) {
	src, err := windows.UTF16FromString(s)
	if err != nil {
		return
	}
	if len(src) > len(dst) {
		src = src[:len(dst)]
		src[len(src)-1] = 0
	}
	copy(dst, src)
}
