# CookieGuard

A lightweight, open-source browser cookie protection system for Windows.

## Why?

Cookie stealers (Lumma, Rakhni, RedLine, etc.) target browser cookies to hijack authenticated sessions. CookieGuard monitors cookie access and alerts on suspicious processes.

## Features

- Real-time monitoring of browser cookie files
- Process-based risk scoring (allowlist browsers, flag suspicious processes)
- Optional process termination (with admin privileges)
- Minimal resource usage

## Installation

```bash
# Install via GitHub
gh repo clone cookieguard

# Build from source
go build -o cookieguard cmd/cookieguard/main.go
```

## Usage

```bash
# Start monitoring (default)
cookieguard

# Install as startup (HKCU\Run)
cookieguard install

# Scan for active cookie access
cookieguard scan
```

## Threat Analysis

- **Lumma**: Uses Chrome DevTools Protocol to bypass ABE (App-Bound Encryption)
- **RedLine**: Steals via DPAPI decryption of Local State
- **Rakhni**: Targets browser cookies via process injection

## Technical Approach

1. Monitors browser cookie directories (Chrome, Edge, Firefox)
2. Detects file reads via `ReadDirectoryChangesW`
3. Maps process handles to identify accessors
4. Flags processes not in browser allowlist

## License

MIT (See LICENSE file)