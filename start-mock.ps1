<#
.SYNOPSIS
  Starts the mock TSSA endpoint (with its Cloudflare tunnel), opens the web console and prints
  the public URL to use as the HAC connector's TSSA host.

.PARAMETER NewTunnel
  Stop the current Cloudflare tunnel first and start a new one (the quick-tunnel URL changes).
  Use this when the tunnel URL has stopped working (for example after a VPN dropped it).

.PARAMETER ConnectorDir
  Folder of the on-prem TSSA connector. When given, its config\application.properties `host=`
  is updated to the tunnel host if it differs (the connector must then be restarted).

.PARAMETER NoBrowser
  Don't open the web console.

.EXAMPLE
  .\start-mock.ps1
  .\start-mock.ps1 -NewTunnel -ConnectorDir C:\path\to\connector
#>
param(
  [switch]$NewTunnel,
  [string]$ConnectorDir,
  [switch]$NoBrowser,
  [int]$HttpPort = 9842,
  [int]$TimeoutSec = 90
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$consoleUrl = "http://localhost:$HttpPort/"

function Get-MockInfo {
  try { Invoke-RestMethod -Uri "http://localhost:$HttpPort/mock/info" -TimeoutSec 3 } catch { $null }
}

function Get-MockPid {
  $c = Get-NetTCPConnection -LocalPort $HttpPort -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($c) { $c.OwningProcess }
}

if (-not (Get-Command node -ErrorAction SilentlyContinue)) { throw 'Node.js (node.exe) is not on PATH.' }

if ($NewTunnel) {
  Write-Host 'Stopping the current Cloudflare tunnel...'
  & node (Join-Path $root 'server.js') --stop-tunnel | Write-Host
  # A running mock would just restart the tunnel itself; restart the mock so it starts cleanly.
  $mockPid = Get-MockPid
  if ($mockPid) { Stop-Process -Id $mockPid -Force; Start-Sleep -Seconds 1 }
}

if (-not (Get-MockPid)) {
  Write-Host 'Starting mock TSSA...'
  $log = Join-Path $root 'data\mock-console.log'
  New-Item -ItemType Directory -Force (Join-Path $root 'data') | Out-Null
  # cmd redirects the output; the window is hidden and the mock outlives this script.
  Start-Process -FilePath cmd.exe -ArgumentList '/c', "node server.js > `"$log`" 2>&1" -WorkingDirectory $root -WindowStyle Hidden
} else {
  Write-Host "Mock TSSA is already running (pid $(Get-MockPid))."
}

# Wait for the mock and a connected tunnel with a URL.
$deadline = (Get-Date).AddSeconds($TimeoutSec)
$info = $null
do {
  Start-Sleep -Seconds 1
  $info = Get-MockInfo
  $t = if ($info) { $info.tunnel } else { $null }
} until (($t -and $t.url -and $t.status -eq 'connected') -or (Get-Date) -gt $deadline)

if (-not $info) { throw "Mock did not start; see $(Join-Path $root 'data\mock-console.log')" }
$t = $info.tunnel
if (-not $t.url) {
  Write-Warning "No tunnel URL yet (status: $($t.status)). $($t.error)"
} else {
  # Check the URL really reaches the mock through Cloudflare.
  $reachable = $false
  for ($i = 0; $i -lt 10 -and -not $reachable; $i++) {
    try { Invoke-RestMethod -Uri "$($t.url)/rest/actuator/info" -TimeoutSec 10 | Out-Null; $reachable = $true } catch { Start-Sleep -Seconds 3 }
  }
  if (-not $reachable) {
    Write-Warning "The tunnel URL does not answer yet. If it keeps failing (a VPN can block it), run: .\start-mock.ps1 -NewTunnel"
  }
}

if ($ConnectorDir -and $t.host) {
  $props = Join-Path $ConnectorDir 'config\application.properties'
  if (-not (Test-Path $props)) { throw "Not found: $props" }
  $text = Get-Content $props -Raw
  $current = if ($text -match '(?m)^host=(.*)$') { $Matches[1].Trim() } else { $null }
  if ($current -ne $t.host) {
    $text = if ($current -ne $null) { $text -replace '(?m)^host=.*$', "host=$($t.host)" } else { $text.TrimEnd() + "`r`nhost=$($t.host)`r`n" }
    [IO.File]::WriteAllText($props, $text)
    Write-Host "Updated connector host: $current -> $($t.host). Restart the connector to use it." -ForegroundColor Yellow
  } else {
    Write-Host 'Connector already points at this tunnel.'
  }
}

if (-not $NoBrowser) { Start-Process $consoleUrl }

Write-Host ''
Write-Host "Mock TSSA console : $consoleUrl"
if ($t.url) {
  Write-Host "Cloudflare URL    : $($t.url)" -ForegroundColor Green
  Write-Host "HAC connector     : Host Name = $($t.host), Application Port = 443"
  try { Set-Clipboard -Value $t.host; Write-Host '(host name copied to the clipboard)' } catch { }
}
