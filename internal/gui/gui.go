// Package gui provides a small native Win32 window that shows live CookieGuard
// events and lets the user toggle enforcement. It uses only user32/gdi32 through
// LazyDLL, so it needs no CGO and no third-party GUI toolkit.
package gui

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	wmDestroy = 0x0002
	wmSize    = 0x0005
	wmClose   = 0x0010
	wmCommand = 0x0111
	wmSetFont = 0x0030
	wmAppend  = 0x8000 + 1
	wmStatus  = 0x8000 + 2

	wsOverlappedWindow = 0x00CF0000
	wsVisible          = 0x10000000
	wsChild            = 0x40000000
	wsVScroll          = 0x00200000
	wsTabStop          = 0x00010000
	esMultiline        = 0x0004
	esAutovscroll      = 0x0040
	esReadonly         = 0x0800
	cwUseDefault       = 0x80000000
	swShow             = 5

	emSetsel     = 0x00B1
	emReplaceSel = 0x00C2

	idStatus  = 1001
	idLog     = 1002
	idProtect = 1003
	idOpenLog = 1004
	idClear   = 1005
	idQuit    = 1006

	defaultGUIFont = 17
	idcArrow       = 32512
)

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	gdi32    = windows.NewLazySystemDLL("gdi32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	pRegisterClassExW = user32.NewProc("RegisterClassExW")
	pCreateWindowExW  = user32.NewProc("CreateWindowExW")
	pDefWindowProcW   = user32.NewProc("DefWindowProcW")
	pDestroyWindow    = user32.NewProc("DestroyWindow")
	pDestroyIcon      = user32.NewProc("DestroyIcon")
	pPostQuitMessage  = user32.NewProc("PostQuitMessage")
	pGetMessageW      = user32.NewProc("GetMessageW")
	pTranslateMessage = user32.NewProc("TranslateMessage")
	pDispatchMessageW = user32.NewProc("DispatchMessageW")
	pSendMessageW     = user32.NewProc("SendMessageW")
	pPostMessageW     = user32.NewProc("PostMessageW")
	pShowWindow       = user32.NewProc("ShowWindow")
	pSetForegroundWin = user32.NewProc("SetForegroundWindow")
	pBringWindowToTop = user32.NewProc("BringWindowToTop")
	pUpdateWindow     = user32.NewProc("UpdateWindow")
	pSetWindowTextW   = user32.NewProc("SetWindowTextW")
	pGetClientRect    = user32.NewProc("GetClientRect")
	pMoveWindow       = user32.NewProc("MoveWindow")
	pLoadImageW       = user32.NewProc("LoadImageW")
	pLoadCursorW      = user32.NewProc("LoadCursorW")
	pGetModuleHandleW = kernel32.NewProc("GetModuleHandleW")
	pGetStockObject   = gdi32.NewProc("GetStockObject")
)

type rect struct{ Left, Top, Right, Bottom int32 }

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

// Options configures the window.
type Options struct {
	Title         string
	IconBytes     []byte
	Protect       *atomic.Bool
	ProtectReview *atomic.Bool
	OnOpenLog     func()
	OnQuit        func()
}

// GUI is a native window showing live events.
type GUI struct {
	hwnd   windows.Handle
	log    windows.Handle
	status windows.Handle
	button struct {
		protect, open, clear, quit windows.Handle
	}
	opts  Options
	class *uint16
	hicon windows.Handle

	mu       sync.Mutex
	queue    []string
	statusTx string
}

var active atomic.Pointer[GUI]

func wndProc(hwnd, message, wparam, lparam uintptr) uintptr {
	g := active.Load()
	switch uint32(message) {
	case wmSize:
		if g != nil {
			g.layout()
		}
		return 0
	case wmCommand:
		if g != nil {
			g.onCommand(int(uint16(wparam)))
		}
		return 0
	case wmAppend:
		if g != nil {
			g.drain()
		}
		return 0
	case wmStatus:
		if g != nil {
			g.mu.Lock()
			text := g.statusTx
			g.mu.Unlock()
			setText(g.status, text)
		}
		return 0
	case wmClose:
		if g != nil && g.opts.OnQuit != nil {
			g.opts.OnQuit()
		}
		pDestroyWindow.Call(hwnd)
		return 0
	case wmDestroy:
		pPostQuitMessage.Call(0)
		return 0
	}
	ret, _, _ := pDefWindowProcW.Call(hwnd, message, wparam, lparam)
	return ret
}

// New creates and shows the window, then runs its message loop on a locked OS
// thread. It returns once the window exists.
func New(opts Options) (*GUI, error) {
	g := &GUI{opts: opts}
	if len(opts.IconBytes) > 0 {
		if h, err := loadIconFromBytes(opts.IconBytes); err == nil {
			g.hicon = h
		}
	}
	ready := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := g.create(opts); err != nil {
			ready <- err
			return
		}
		ready <- nil
		g.loop()
	}()
	if err := <-ready; err != nil {
		return nil, err
	}
	return g, nil
}

func (g *GUI) create(opts Options) error {
	className, err := windows.UTF16PtrFromString("CookieGuardMain")
	if err != nil {
		return err
	}
	g.class = className
	hInstance, _, _ := pGetModuleHandleW.Call(0)
	cursor, _, _ := pLoadCursorW.Call(0, idcArrow)

	wc := wndClassEx{
		CbSize:        uint32(unsafe.Sizeof(wndClassEx{})),
		LpfnWndProc:   windows.NewCallback(wndProc),
		HInstance:     windows.Handle(hInstance),
		HCursor:       windows.Handle(cursor),
		HbrBackground: 6, // COLOR_WINDOW + 1
		LpszClassName: className,
		HIcon:         g.hicon,
		HIconSm:       g.hicon,
	}
	if r, _, e := pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		return fmt.Errorf("RegisterClassEx: %w", e)
	}
	title, _ := windows.UTF16PtrFromString(opts.Title)
	hwnd, _, e := pCreateWindowExW.Call(0,
		uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(title)),
		uintptr(uint32(wsOverlappedWindow|wsVisible)),
		80, 80, 820, 560,
		0, 0, hInstance, 0)
	if hwnd == 0 {
		return fmt.Errorf("CreateWindowEx: %w", e)
	}
	g.hwnd = windows.Handle(hwnd)
	active.Store(g)

	font, _, _ := pGetStockObject.Call(defaultGUIFont)

	g.status = g.child("STATIC", "Durum: baslatiliyor...", 0, idStatus)
	g.log = g.child("EDIT", "", uint32(esMultiline|esAutovscroll|esReadonly|wsVScroll), idLog)
	g.button.protect = g.child("BUTTON", protectLabel(opts), wsTabStop, idProtect)
	g.button.open = g.child("BUTTON", "Kaydi Ac", wsTabStop, idOpenLog)
	g.button.clear = g.child("BUTTON", "Temizle", wsTabStop, idClear)
	g.button.quit = g.child("BUTTON", "Cikis", wsTabStop, idQuit)

	if font != 0 {
		for _, h := range []windows.Handle{g.status, g.log, g.button.protect, g.button.open, g.button.clear, g.button.quit} {
			pSendMessageW.Call(uintptr(h), wmSetFont, font, 1)
		}
	}
	g.layout()
	pShowWindow.Call(hwnd, swShow)
	pBringWindowToTop.Call(hwnd)
	pSetForegroundWin.Call(hwnd)
	pUpdateWindow.Call(hwnd)
	return nil
}

func (g *GUI) child(class, text string, style uint32, id int) windows.Handle {
	c, _ := windows.UTF16PtrFromString(class)
	t, _ := windows.UTF16PtrFromString(text)
	ex := uintptr(0)
	if class == "EDIT" {
		ex = 0x200 // WS_EX_CLIENTEDGE
	}
	h, _, _ := pCreateWindowExW.Call(ex, uintptr(unsafe.Pointer(c)), uintptr(unsafe.Pointer(t)),
		uintptr(wsChild|wsVisible|style), 0, 0, 100, 100,
		uintptr(g.hwnd), uintptr(id), 0, 0)
	return windows.Handle(h)
}

func (g *GUI) layout() {
	var r rect
	pGetClientRect.Call(uintptr(g.hwnd), uintptr(unsafe.Pointer(&r)))
	w := r.Right - r.Left
	h := r.Bottom - r.Top
	const pad = 10
	statusH, btnH := int32(22), int32(32)

	move(g.status, pad, pad, w-2*pad, statusH)
	logTop := pad + statusH + 6
	logBottom := h - pad - btnH - 6
	move(g.log, pad, logTop, w-2*pad, logBottom-logTop)

	btnY := h - pad - btnH
	move(g.button.protect, pad, btnY, 220, btnH)
	move(g.button.open, pad+230, btnY, 130, btnH)
	move(g.button.clear, pad+370, btnY, 110, btnH)
	move(g.button.quit, pad+490, btnY, 110, btnH)
}

func (g *GUI) onCommand(id int) {
	switch id {
	case idProtect:
		if g.opts.Protect != nil {
			next := !g.opts.Protect.Load()
			g.opts.Protect.Store(next)
			if !next && g.opts.ProtectReview != nil {
				g.opts.ProtectReview.Store(false)
			}
			g.Append(fmt.Sprintf("[%s] %s", nowStamp(), protectLabel(g.opts)))
		}
		setText(g.button.protect, protectLabel(g.opts))
	case idOpenLog:
		if g.opts.OnOpenLog != nil {
			go g.opts.OnOpenLog()
		}
	case idClear:
		setText(g.log, "")
	case idQuit:
		if g.opts.OnQuit != nil {
			g.opts.OnQuit()
		}
		pDestroyWindow.Call(uintptr(g.hwnd))
	}
}

func protectLabel(opts Options) string {
	if opts.Protect != nil && opts.Protect.Load() {
		return "Koruma: ACIK (kapat)"
	}
	return "Koruma: kapali (ac)"
}

// Append queues a line for the log view.
func (g *GUI) Append(line string) {
	g.mu.Lock()
	g.queue = append(g.queue, line)
	g.mu.Unlock()
	pPostMessageW.Call(uintptr(g.hwnd), wmAppend, 0, 0)
}

// SetStatus updates the status label.
func (g *GUI) SetStatus(text string) {
	g.mu.Lock()
	g.statusTx = text
	g.mu.Unlock()
	pPostMessageW.Call(uintptr(g.hwnd), wmStatus, 0, 0)
}

func (g *GUI) drain() {
	g.mu.Lock()
	lines := g.queue
	g.queue = nil
	g.mu.Unlock()
	if len(lines) == 0 {
		return
	}
	var text string
	for _, l := range lines {
		text += l + "\r\n"
	}
	appendText(g.log, text)
}

func (g *GUI) loop() {
	var m msg
	for {
		r, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			return
		}
		pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		pDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

// Close destroys the window and stops the message loop.
func (g *GUI) Close() {
	if g == nil || g.hwnd == 0 {
		return
	}
	pPostMessageW.Call(uintptr(g.hwnd), wmClose, 0, 0)
	if g.hicon != 0 {
		pDestroyIcon.Call(uintptr(g.hicon))
	}
	active.Store(nil)
}

func setText(h windows.Handle, text string) {
	p, err := windows.UTF16PtrFromString(text)
	if err != nil {
		return
	}
	pSetWindowTextW.Call(uintptr(h), uintptr(unsafe.Pointer(p)))
}

func appendText(edit windows.Handle, text string) {
	pSendMessageW.Call(uintptr(edit), emSetsel, ^uintptr(0), ^uintptr(0))
	p, err := windows.UTF16PtrFromString(text)
	if err != nil {
		return
	}
	pSendMessageW.Call(uintptr(edit), emReplaceSel, 0, uintptr(unsafe.Pointer(p)))
}

func move(h windows.Handle, x, y, w, hh int32) {
	pMoveWindow.Call(uintptr(h), uintptr(x), uintptr(y), uintptr(w), uintptr(hh), 1)
}

func nowStamp() string { return time.Now().Format("15:04:05") }

func loadIconFromBytes(data []byte) (windows.Handle, error) {
	f, err := os.CreateTemp("", "cookieguard-gui-*.ico")
	if err != nil {
		return 0, err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return 0, err
	}
	f.Close()
	pp, err := windows.UTF16PtrFromString(f.Name())
	if err != nil {
		return 0, err
	}
	h, _, e := pLoadImageW.Call(0, uintptr(unsafe.Pointer(pp)), 1, 0, 0, 0x10)
	if h == 0 {
		return 0, e
	}
	return windows.Handle(h), nil
}
