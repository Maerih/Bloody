# SCIAT Agent (Windows) — proprietary, (c) SCIAT AFRICA.
# Checks in with the SCIAT / Bloody platform: liveness, host facts, isolation state, engines.
# Started by the "SCIAT Agent" Windows service (SCIATAgent.exe); can also be run by hand:
#   sciat-agent.ps1 run | once | status
param([ValidateSet('run', 'once', 'status')][string]$Command = 'run')
$ErrorActionPreference = 'Stop'
$AgentVersion = '1.0.0'
$Home_ = Join-Path $env:ProgramFiles 'SCIAT\Agent'
$DataDir = Join-Path $env:ProgramData 'SCIAT\Agent'
$Conf = Get-Content (Join-Path $DataDir 'agent.json') -Raw | ConvertFrom-Json
if (-not $Conf.platformUrl -or -not $Conf.agentToken) { throw "agent.json is incomplete - reinstall the SCIAT Agent" }
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

function Write-AgentLog([string]$Message, [string]$Type = 'Information') {
  try { Write-EventLog -LogName Application -Source 'SCIAT Agent' -EventId 1000 -EntryType $Type -Message $Message -ErrorAction Stop } catch { }
}

function Get-Isolation {
  $iso = Join-Path $Home_ 'bloody-isolate.ps1'
  if (-not (Test-Path $iso)) { return @{ state = 'unknown' } }
  $out = @(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $iso status 2>$null)
  if ($out.Count -gt 0 -and $out[0] -eq 'isolated') {
    $mode = ($out | Where-Object { $_ -like 'mode=*' } | Select-Object -First 1) -replace '^mode=', ''
    if (-not $mode) { $mode = 'unknown' }
    return @{ state = 'isolated'; mode = $mode }
  }
  return @{ state = 'not_isolated' }
}

function Get-Engines {
  $engines = @{}
  foreach ($name in 'WazuhSvc', 'osqueryd', 'Velociraptor', 'Sysmon64', 'WinDefend') {
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($svc) { $engines[$name] = "$($svc.Status)".ToLowerInvariant() }
  }
  return $engines
}

function Invoke-Checkin {
  $os = Get-CimInstance Win32_OperatingSystem
  $ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
      Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
      Select-Object -ExpandProperty IPAddress -First 16)
  $body = @{
    hostname      = $env:COMPUTERNAME
    os            = "$($os.Caption) $($os.Version)".Trim()
    version       = $AgentVersion
    ips           = $ips
    uptimeSeconds = [int]((Get-Date) - $os.LastBootUpTime).TotalSeconds
    isolation     = Get-Isolation
    engines       = Get-Engines
  } | ConvertTo-Json -Depth 4 -Compress
  Invoke-RestMethod -Method Post -Uri "$($Conf.platformUrl)/api/v1/agent/heartbeat" -TimeoutSec 20 `
    -Headers @{ authorization = "Bearer $($Conf.agentToken)" } -ContentType 'application/json' -Body $body
}

switch ($Command) {
  'once' { Invoke-Checkin | ConvertTo-Json -Compress }
  'status' {
    "SCIAT Agent $AgentVersion"
    "platform: $($Conf.platformUrl)"
    $last = Join-Path $DataDir 'last-checkin'
    if (Test-Path $last) { "last check-in: $(Get-Content $last)" } else { 'last check-in: never' }
  }
  'run' {
    Write-AgentLog "SCIAT Agent $AgentVersion starting (platform $($Conf.platformUrl))"
    $failures = 0
    while ($true) {
      try {
        $resp = Invoke-Checkin
        $failures = 0
        (Get-Date).ToUniversalTime().ToString('s') + 'Z' | Set-Content -Path (Join-Path $DataDir 'last-checkin') -Encoding ascii
        $delay = if ($resp.pollSeconds) { [int]$resp.pollSeconds } else { 60 }
      } catch {
        $failures++
        # Back off while the platform is unreachable (max 10 minutes).
        $delay = 60 * [Math]::Min($failures, 10)
        if ($failures % 5 -eq 1) { Write-AgentLog "check-in failed ($failures in a row): $($_.Exception.Message)" 'Warning' }
      }
      Start-Sleep -Seconds $delay
    }
  }
}
