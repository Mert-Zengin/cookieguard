// Package assets exposes build-time embedded files (currently the app icon).
package assets

import _ "embed"

// Icon is the multi-size application icon used by the tray and embedded into
// the executable as a Windows resource by cmd/cookieguard/rsrc.syso.
//
//go:embed cookieguard.ico
var Icon []byte
