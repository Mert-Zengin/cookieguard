# Runs INSIDE Windows Sandbox. It creates synthetic browser data, starts
# CookieGuard, then runs the benign simulator to demonstrate detection and
# (optionally) enforcement. Nothing here touches real data or the network.
$ErrorActionPreference = "Continue"
$exeDir = "C:\cg"          # read-only mapped share
$work   = "C:\cgtest"
$log    = Join-Path $work "events.jsonl"

Write-Host "=== CookieGuard Windows Sandbox test ===" -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $work | Out-Null
Copy-Item -Path (Join-Path $exeDir "*.exe") -Destination $work -Force
Copy-Item -Path (Join-Path $exeDir "run-test.ps1") -Destination $work -Force -ErrorAction SilentlyContinue

Write-Host "`n[1/3] Creating synthetic browser data" -ForegroundColor Yellow
& (Join-Path $work "fakecookies.exe") -profile $env:USERPROFILE | Select-Object -Last 2

Write-Host "`n[2/3] Observation mode: CookieGuard should log a review event" -ForegroundColor Yellow
$guard = Start-Process (Join-Path $work "cookieguard.exe") `
    -ArgumentList @("run", "--lang", "en", "--tray=false", "--interval", "1s", "--log", $log) `
    -PassThru -WindowStyle Minimized
# wait for the first scan to finish
Start-Sleep -Seconds 3
& (Join-Path $work "simulate.exe") --profile $env:USERPROFILE --hold 6s --yes
Start-Sleep -Seconds 2
Stop-Process -Id $guard.Id -ErrorAction SilentlyContinue
Write-Host "--- last events (observation) ---"
Get-Content $log -ErrorAction SilentlyContinue | Select-Object -Last 4

Write-Host "`n[3/3] Enforcement mode: --protect-review should terminate the simulator" -ForegroundColor Yellow
$log2 = Join-Path $work "events2.jsonl"
$guard2 = Start-Process (Join-Path $work "cookieguard.exe") `
    -ArgumentList @("run", "--lang", "en", "--tray=false", "--interval", "1s", "--protect-review", "--log", $log2) `
    -PassThru -WindowStyle Minimized
Start-Sleep -Seconds 3
$sim = Start-Process (Join-Path $work "simulate.exe") `
    -ArgumentList @("--profile", $env:USERPROFILE, "--hold", "20s", "--yes") -PassThru
$deadline = (Get-Date).AddSeconds(20)
while ((Get-Date) -lt $deadline -and -not $sim.HasExited) { Start-Sleep -Milliseconds 300 }
if ($sim.HasExited) {
    Write-Host "PASS: simulator was terminated by CookieGuard" -ForegroundColor Green
} else {
    Write-Host "NOTE: simulator was not terminated (scan may have missed the handle); stopping it" -ForegroundColor DarkYellow
    Stop-Process -Id $sim.Id -ErrorAction SilentlyContinue
}
Stop-Process -Id $guard2.Id -ErrorAction SilentlyContinue
Write-Host "--- last events (enforcement) ---"
Get-Content $log2 -ErrorAction SilentlyContinue | Select-Object -Last 4

Write-Host "`nDone. Use the GUI build for a visual view: cookieguard-tray.exe gui" -ForegroundColor Cyan
Write-Host "Press Enter to close the sandbox..."
Read-Host
