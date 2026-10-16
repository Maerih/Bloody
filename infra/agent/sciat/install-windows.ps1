# SCIAT Agent installer for Windows — proprietary, (c) SCIAT AFRICA.
#
#   Run in PowerShell as Administrator:
#   .\install-sciat.ps1 -AccountKey sak_... -OrgKey <organization key>
#   .\install-sciat.ps1 -Uninstall
#
# Installs the "SCIAT Agent" Windows service (SCIATAgent). Its executable is compiled here from
# our own source with the .NET Framework compiler that ships with Windows.
# The platform address below is filled in by the platform that served this script.
param(
  [string]$AccountKey,
  [string]$OrgKey,
  [string]$PlatformUrl = '__PLATFORM_URL__',
  [switch]$Uninstall
)
$ErrorActionPreference = 'Stop'
$AgentVersion = '1.1.0'
$ServiceName = 'SCIATAgent'
$Home_ = Join-Path $env:ProgramFiles 'SCIAT\Agent'
$DataDir = Join-Path $env:ProgramData 'SCIAT\Agent'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

function Say([string]$m) { Write-Host 'SCIAT ' -ForegroundColor Red -NoNewline; Write-Host $m }
function Fail([string]$m) { Write-Host "SCIAT agent install: $m" -ForegroundColor Red; exit 1 }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Fail 'run PowerShell as Administrator' }

function Remove-AgentService {
  if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
  }
}

if ($Uninstall) {
  Remove-AgentService
  $iso = Join-Path $Home_ 'bloody-isolate.ps1'
  if (Test-Path $iso) { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $iso release 2>$null | Out-Null }
  Remove-Item -Recurse -Force $Home_, $DataDir -ErrorAction SilentlyContinue
  Say 'SCIAT Agent removed.'
  exit 0
}

if (-not $AccountKey -or -not $OrgKey) { Fail 'usage: install-sciat.ps1 -AccountKey sak_... -OrgKey <organization key>  |  -Uninstall' }
if ($AccountKey -notmatch '^sak_[0-9a-f]{32}_[A-Za-z0-9_-]{32,64}$') { Fail 'the account key looks wrong (expected sak_...)' }
if ($OrgKey -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$') { Fail 'the organization key looks wrong' }
if ($PlatformUrl -notmatch '^https?://[A-Za-z0-9.:\[\]_-]+(/[A-Za-z0-9._~/-]*)?$') { Fail "invalid platform URL '$PlatformUrl'" }
$PlatformUrl = $PlatformUrl.TrimEnd('/')

$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
if (-not (Test-Path $csc)) { Fail '.NET Framework 4.x is required (csc.exe not found)' }

# Enroll this computer.
$os = Get-CimInstance Win32_OperatingSystem
$ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
    Select-Object -ExpandProperty IPAddress -First 16)
$machineId = (Get-CimInstance Win32_ComputerSystemProduct).UUID
$enroll = @{
  accountKey = $AccountKey; organizationKey = $OrgKey; hostname = $env:COMPUTERNAME; platform = 'windows'
  os = "$($os.Caption) $($os.Version)".Trim(); version = $AgentVersion; ips = $ips
}
if ($machineId) { $enroll.machineId = "$machineId" }
Say "Enrolling $env:COMPUTERNAME with $PlatformUrl ..."
try {
  $resp = Invoke-RestMethod -Method Post -Uri "$PlatformUrl/api/v1/agent/enroll" -ContentType 'application/json' -Body ($enroll | ConvertTo-Json -Compress) -TimeoutSec 30
} catch {
  $detail = $_.ErrorDetails.Message
  if ($detail) { try { $detail = ($detail | ConvertFrom-Json).error.message } catch { } }
  Fail "enrollment refused: $(if ($detail) { $detail } else { $_.Exception.Message })"
}
if ("$($resp.token)" -notmatch '^sat_') { Fail 'the platform did not return an agent token' }

Remove-AgentService
Say "Installing files to $Home_ ..."
New-Item -ItemType Directory -Force -Path $Home_, $DataDir | Out-Null
foreach ($f in 'sciat-agent.ps1', 'SciatAgentService.cs', 'bloody-isolate.ps1') {
  Invoke-WebRequest -UseBasicParsing -Uri "$PlatformUrl/api/v1/agent/files/$f" -OutFile (Join-Path $Home_ $f) -TimeoutSec 60
}

# Configuration readable only by SYSTEM and Administrators (it holds the agent token).
$confPath = Join-Path $DataDir 'agent.json'
@{ platformUrl = $PlatformUrl; agentToken = "$($resp.token)"; organizationId = "$($resp.organizationId)" } | ConvertTo-Json | Set-Content -Path $confPath -Encoding ascii
& icacls.exe $DataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null

# Build the service executable from our own source.
$exe = Join-Path $Home_ 'SCIATAgent.exe'
& $csc /nologo /target:exe /optimize+ "/out:$exe" /reference:System.ServiceProcess.dll (Join-Path $Home_ 'SciatAgentService.cs') | Out-Host
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $exe)) { Fail 'could not build SCIATAgent.exe' }

if (-not [Diagnostics.EventLog]::SourceExists('SCIAT Agent')) { New-EventLog -LogName Application -Source 'SCIAT Agent' }
New-Service -Name $ServiceName -BinaryPathName "`"$exe`"" -DisplayName 'SCIAT Agent' -StartupType Automatic `
  -Description 'SCIAT AFRICA endpoint agent: keeps this computer connected to the SCIAT security platform.' | Out-Null
& sc.exe failure $ServiceName reset= 86400 actions= restart/15000/restart/60000/restart/300000 | Out-Null
Start-Service -Name $ServiceName

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Home_ 'sciat-agent.ps1') once 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) {
  Say 'SCIAT Agent installed and checked in. It now appears under Agents in the Command Center.'
} else {
  Say 'SCIAT Agent installed; the first check-in failed - see the Application event log (source "SCIAT Agent").'
}
