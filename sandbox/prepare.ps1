# Prepares a Windows Sandbox test kit on the HOST.
#   ./sandbox/prepare.ps1 -Version v1.3.0
# It builds the executables, copies them plus run-test.ps1 into sandbox\share,
# and generates sandbox\CookieGuard.generated.wsb with the correct absolute path.
# Then double-click that .wsb (Windows Sandbox must be enabled).
param(
    [string]$Version = "v1.3.0"
)

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$share = Join-Path $PSScriptRoot "share"
Remove-Item -LiteralPath $share -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $share -Force | Out-Null

Write-Host "Building release executables..." -ForegroundColor Cyan
go build -trimpath -ldflags "-X main.version=$Version" -o (Join-Path $share "cookieguard.exe") ./cmd/cookieguard
go build -trimpath -ldflags "-X main.version=$Version -H=windowsgui" -o (Join-Path $share "cookieguard-tray.exe") ./cmd/cookieguard
go build -o (Join-Path $share "simulate.exe") ./tools/simulate
go build -o (Join-Path $share "fakecookies.exe") ./tools/fakecookies
go build -o (Join-Path $share "holder.exe") ./tools/holder
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "run-test.ps1") -Destination $share -Force

$abs = (Resolve-Path -LiteralPath $share).Path
$wsb = Join-Path $PSScriptRoot "CookieGuard.generated.wsb"
@"
<Configuration>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>$abs</HostFolder>
      <SandboxFolder>C:\cg</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <Networking>Disable</Networking>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <LogonCommand>
    <Command>powershell.exe -NoExit -ExecutionPolicy Bypass -File C:\cg\run-test.ps1</Command>
  </LogonCommand>
</Configuration>
"@ | Set-Content -LiteralPath $wsb -Encoding ascii

Write-Host ""
Write-Host "Sandbox kit ready." -ForegroundColor Green
Write-Host "  share : $share"
Write-Host "  config: $wsb"
Write-Host "Double-click the .wsb to launch Windows Sandbox and run the test."
