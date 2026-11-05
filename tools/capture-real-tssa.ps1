<#
.SYNOPSIS
  Captures the REST responses HAC reads from a real TSSA server, so the mock can copy their exact
  JSON formats. Run it on a machine that can reach the TSSA application server.

.DESCRIPTION
  Makes the same read-only GET calls the HAC connector makes (see restapi_default.log) and saves
  each response as JSON under .\tssa-capture\. Nothing is changed on the TSSA server.
  Session ids are removed from the saved files. The password is only sent to TSSA.

.EXAMPLE
  .\capture-real-tssa.ps1 -TssaHost tssa.example.com -User BLAdmin
  .\capture-real-tssa.ps1 -TssaHost tssa.example.com -User BLAdmin -PatchingJobId 1951 -PatchingRunId 10910 -ComplianceJobId 1551 -ComplianceRunId 10915
#>
param(
  [Parameter(Mandatory)] [string]$TssaHost,
  [int]$Port = 9843,
  [Parameter(Mandatory)] [string]$User,
  [string]$Role = 'BLAdmins',
  [ValidateSet('SRP', 'RSSO')] [string]$AuthType = 'SRP',
  [int]$PatchingJobId, [int]$PatchingRunId,
  [int]$ComplianceJobId, [int]$ComplianceRunId,
  [int[]]$CatalogIds,   # catalogs to capture in detail; default is the first 3 listed
  [string]$OutDir = (Join-Path (Get-Location) 'tssa-capture')
)

$ErrorActionPreference = 'Stop'
# TSSA uses a self-signed certificate by default.
if (-not ([System.Management.Automation.PSTypeName]'TrustAllCerts').Type) {
  Add-Type @'
using System.Net; using System.Security.Cryptography.X509Certificates;
public class TrustAllCerts : ICertificatePolicy { public bool CheckValidationResult(ServicePoint s, X509Certificate c, WebRequest r, int p) { return true; } }
'@
}
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCerts
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

$base = "https://${TssaHost}:$Port/rest"
New-Item -ItemType Directory -Force $OutDir | Out-Null

$cred = Get-Credential -UserName $User -Message "TSSA password for $User"
$loginBody = @{ user_name = $User; password = $cred.GetNetworkCredential().Password; authentication_type = $AuthType; role_name = $Role } | ConvertTo-Json
$login = Invoke-WebRequest -Uri "$base/api/v1/sessions" -Method Post -Body $loginBody -ContentType 'application/json' -UseBasicParsing
$sid = ($login.Content | ConvertFrom-Json).session_id
if (-not $sid) { throw 'Login response has no session_id; see 00-login.json' }
$headers = @{ 'session-id' = $sid; 'role' = $Role; Accept = 'application/json' }

function Save($name, $text) {
  # Strip the live session id (and any service ticket) from what is saved.
  $clean = $text -replace [regex]::Escape($sid), '<session-id>' -replace '"service_ticket"\s*:\s*"[^"]*"', '"service_ticket":"<removed>"'
  [IO.File]::WriteAllText((Join-Path $OutDir "$name.json"), $clean)
}
Save '00-login' $login.Content

function Get-Tssa($name, $path) {
  try {
    $r = Invoke-WebRequest -Uri "$base$path" -Headers $headers -UseBasicParsing
    Save $name $r.Content
    Write-Host ("{0,-28} {1}  ({2} bytes)" -f $name, $path, $r.Content.Length)
    return ($r.Content | ConvertFrom-Json)
  } catch {
    $msg = $_.Exception.Message
    Save $name (@{ path = $path; error = $msg } | ConvertTo-Json)
    Write-Warning "$name $path failed: $msg"
  }
}

$q = 'device_type=server&device_state=Enrolled&page=0&size=1000&additional_detail=true'
Get-Tssa '01-actuator-info' '/actuator/info' | Out-Null
Get-Tssa '02-session' '/api/v1/sessions' | Out-Null
$win = Get-Tssa '03-servers-windows' "/api/v1/servers?$q&os_name=Windows"
Get-Tssa '04-servers-linux' "/api/v1/servers?$q&os_name=Linux" | Out-Null
Get-Tssa '05-servers-all-page' '/api/v1/servers?page=0&size=5' | Out-Null
# First server id from the Windows list, whatever the list key is called.
$sid1 = $null
if ($win) { foreach ($p in $win.PSObject.Properties) { if ($p.Value -is [array] -and $p.Value.Count) { $first = $p.Value[0]; $sid1 = if ($first.id) { $first.id } elseif ($first.server_id) { $first.server_id } else { $null }; break } } }
if ($sid1) { Get-Tssa '06-server-by-id' "/api/v1/servers/$sid1" | Out-Null }

$cats = Get-Tssa '07-catalogs' '/api/v1/catalogs?page=0&size=1000'
$ids = if ($CatalogIds) { $CatalogIds } elseif ($cats.catalogs) { $cats.catalogs | Select-Object -First 3 | ForEach-Object { $_.id } } else { @() }
foreach ($id in $ids) {
  Get-Tssa "08-catalog-$id" "/api/v1/catalogs/$id" | Out-Null
  # Containers can be very large (16 MB for a full Windows catalog), so ask for one page.
  Get-Tssa "09-catalog-$id-containers" "/api/v1/catalogs/$id/containers?page=0&size=20" | Out-Null
  Get-Tssa "10-catalog-$id-patches" "/api/v2/catalogs/$id/patches?page=0&size=20" | Out-Null
}
Get-Tssa '11-nshscript-jobs' '/api/v1/nshscript-jobs?page=0&size=5' | Out-Null
if ($PatchingJobId -and $PatchingRunId) {
  $b = "/api/v1/patching-jobs/$PatchingJobId/jobruns/$PatchingRunId"
  Get-Tssa '12-patching-results' "$b/results" | Out-Null
  Get-Tssa '13-patching-analysis' "$b/results/analysis" | Out-Null
  Get-Tssa '14-patching-analysis-servers' "$b/results/analysis/servers/" | Out-Null
}
if ($ComplianceJobId -and $ComplianceRunId) {
  $b = "/api/v1/compliance-jobs/$ComplianceJobId/jobruns/$ComplianceRunId"
  Get-Tssa '15-compliance-results-servers' "$b/results/servers/" | Out-Null
  Get-Tssa '16-compliance-rules' "$b/results/rules" | Out-Null
}

try { Invoke-WebRequest -Uri "$base/api/v1/sessions" -Method Delete -Headers $headers -UseBasicParsing | Out-Null } catch { }
Write-Host "`nSaved to $OutDir. Check the files for anything you don't want to share (host names, IPs), then send the folder path."
