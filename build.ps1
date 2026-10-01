# Builds CookieGuard reproducibly on Windows.
# Usage:  ./build.ps1              -> version v1.3-dev
#         ./build.ps1 -Version v1.3
param(
    [string]$Version = "v1.3-dev"
)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

Write-Host "1/6 icon" -ForegroundColor Cyan
go run ./tools/genicon

Write-Host "2/6 resources (icon + manifest)" -ForegroundColor Cyan
go run github.com/akavel/rsrc@v0.10.2 -manifest cmd/cookieguard/cookieguard.manifest -ico assets/cookieguard.ico -o cmd/cookieguard/rsrc.syso

Write-Host "3/6 tests" -ForegroundColor Cyan
go test ./...

Write-Host "4/6 vet" -ForegroundColor Cyan
go vet ./...

Write-Host "5/6 console build" -ForegroundColor Cyan
go build -trimpath -ldflags "-X main.version=$Version" -o cookieguard.exe ./cmd/cookieguard

Write-Host "6/6 tray (windowless) build" -ForegroundColor Cyan
go build -trimpath -ldflags "-X main.version=$Version -H=windowsgui" -o cookieguard-tray.exe ./cmd/cookieguard

Write-Host "Done." -ForegroundColor Green
Get-FileHash .\cookieguard.exe, .\cookieguard-tray.exe -Algorithm SHA256 | Format-Table -AutoSize
