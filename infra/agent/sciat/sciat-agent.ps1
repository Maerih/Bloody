# SCIAT Agent (Windows) — proprietary, (c) SCIAT AFRICA.
# Checks in with the SCIAT / Bloody platform: liveness, host facts, isolation state, engines.
# Started by the "SCIAT Agent" Windows service (SCIATAgent.exe); can also be run by hand:
#   sciat-agent.ps1 run | once | status
param([ValidateSet('run', 'once', 'status', 'inventory')][string]$Command = 'run')
$ErrorActionPreference = 'Stop'
$AgentVersion = '1.2.0'
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

function Get-PlatformIps {
  $h = ([Uri]$Conf.platformUrl).Host.Trim('[', ']')
  $cache = Join-Path $DataDir 'platform-ips'
  try {
    $ips = @([System.Net.Dns]::GetHostAddresses($h) | ForEach-Object { $_.IPAddressToString } | Select-Object -Unique -First 8)
    if ($ips.Count -gt 0) { $ips | Set-Content -Path $cache -Encoding ascii; return $ips }
  } catch { }
  if (Test-Path $cache) { return @(Get-Content $cache) }
  return @()
}

function Get-DnsServers {
  return @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses } |
      Where-Object { $_ -and $_ -notlike '127.*' -and $_ -ne '::1' -and $_ -notlike 'fec0:*' } | Select-Object -Unique -First 8)
}

function Invoke-Api([string]$Path, $Body) {
  Invoke-RestMethod -Method Post -Uri "$($Conf.platformUrl)/api/v1$Path" -TimeoutSec 20 `
    -Headers @{ authorization = "Bearer $($Conf.agentToken)" } -ContentType 'application/json' -Body ($Body | ConvertTo-Json -Depth 4 -Compress)
}

# Commands from the platform: only isolate / release, only with address-like arguments.
function Invoke-Commands($Response) {
  $ran = $false
  foreach ($c in @($Response.commands)) {
    if (-not $c -or "$($c.id)" -notmatch '^[0-9a-f-]{36}$') { continue }
    $words = @($c.args | ForEach-Object { "$_" })
    $iso = Join-Path $Home_ 'bloody-isolate.ps1'
    if ($words.Count -eq 0 -or $words[0] -notin @('isolate', 'release') -or ($words | Where-Object { $_ -notmatch '^[A-Za-z0-9.,:=/_-]+$' })) {
      $ok = $false; $out = 'refused: unexpected command'
    } elseif (-not (Test-Path $iso)) {
      $ok = $false; $out = 'bloody-isolate.ps1 is missing - reinstall the SCIAT Agent'
    } else {
      $out = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $iso @words 2>&1 | Out-String)
      $ok = ($LASTEXITCODE -eq 0)
      if ($ok) { $out += (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $iso status 2>&1 | Out-String) }
    }
    $status = if ($ok) { 'succeeded' } else { 'failed' }
    Write-AgentLog "command $($words[0]) ($($c.id)): $status"
    if ($out.Length -gt 4000) { $out = $out.Substring(0, 4000) }
    try { Invoke-Api "/agent/commands/$($c.id)/result" @{ status = $status; output = $out } | Out-Null } catch { Write-AgentLog "could not report command $($c.id): $($_.Exception.Message)" 'Warning' }
    $ran = $true
  }
  return $ran
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
    platformIps   = @(Get-PlatformIps)
    dnsServers    = @(Get-DnsServers)
  }
  Invoke-Api '/agent/heartbeat' $body
}

# ---- Host inventory (about every 30 minutes) ------------------------------------------------
function Get-InstalledSoftware {
  $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
  @(Get-ItemProperty -Path $keys -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and -not $_.SystemComponent } |
      Sort-Object DisplayName, DisplayVersion -Unique | Select-Object -First 5000 | ForEach-Object {
        @{ name = "$($_.DisplayName)"; version = "$($_.DisplayVersion)"; publisher = "$($_.Publisher)"; installedAt = "$($_.InstallDate)" }
      })
}

function Get-ServiceInventory {
  @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Select-Object -First 2000 | ForEach-Object {
      @{ name = "$($_.Name)"; displayName = "$($_.DisplayName)"; state = "$($_.State)"; startMode = "$($_.StartMode)"; account = "$($_.StartName)" }
    })
}

function Get-UserInventory {
  $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue | ForEach-Object { ($_.Name -split '\\')[-1] })
  $online = @(Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue | ForEach-Object { if ($_.UserName) { ($_.UserName -split '\\')[-1] } })
  @(Get-LocalUser -ErrorAction SilentlyContinue | Select-Object -First 1000 | ForEach-Object {
      @{ name = "$($_.Name)"; fullName = "$($_.FullName)"; admin = ($admins -contains $_.Name); enabled = [bool]$_.Enabled; loggedIn = ($online -contains $_.Name)
        lastLogon = $(if ($_.LastLogon) { $_.LastLogon.ToUniversalTime().ToString('s') + 'Z' } else { '' }) }
    })
}

function Get-ProcessInventory {
  @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Select-Object -First 2000 | ForEach-Object {
      @{ pid = [int]$_.ProcessId; name = "$($_.Name)"; path = "$($_.ExecutablePath)" }
    })
}

function Get-PortInventory {
  $names = @{}; Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $names[[int]$_.Id] = $_.ProcessName }
  $tcp = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object { @{ protocol = 'tcp'; address = "$($_.LocalAddress)"; port = [int]$_.LocalPort; process = "$($names[[int]$_.OwningProcess])" } })
  $udp = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Where-Object { $_.LocalAddress -notin '127.0.0.1', '::1' } | ForEach-Object { @{ protocol = 'udp'; address = "$($_.LocalAddress)"; port = [int]$_.LocalPort; process = "$($names[[int]$_.OwningProcess])" } })
  @($tcp + $udp | Select-Object -First 2000)
}

# Every product registered with Windows Security Center, plus Microsoft Defender's own status
# (real-time protection, tamper protection, signature age). Windows Server has no Security
# Center, so Defender alone is reported there.
function Get-AntivirusInventory {
  $out = @()
  $mp = $null
  try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch { }
  foreach ($p in @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction SilentlyContinue)) {
    $state = [int]$p.productState
    $enabled = (($state -shr 12) -band 0xF) -in 1, 3
    $upToDate = (($state -shr 4) -band 0xF) -eq 0
    $isDefender = "$($p.displayName)" -match 'Defender'
    $out += @{
      name = "$($p.displayName)"; enabled = $enabled; upToDate = $upToDate
      realTimeProtection = $(if ($isDefender -and $mp) { [bool]$mp.RealTimeProtectionEnabled } else { $null })
      tamperProtection = $(if ($isDefender -and $mp -and $null -ne $mp.IsTamperProtected) { [bool]$mp.IsTamperProtected } else { $null })
      signatureAgeDays = $(if ($isDefender -and $mp) { [int]$mp.AntivirusSignatureAge } else { $null })
    }
  }
  if ($out.Count -eq 0 -and $mp) {
    $out += @{ name = 'Microsoft Defender Antivirus'; enabled = [bool]($mp.AntivirusEnabled -and $mp.AMServiceEnabled); upToDate = $null
      realTimeProtection = [bool]$mp.RealTimeProtectionEnabled; tamperProtection = $(if ($null -ne $mp.IsTamperProtected) { [bool]$mp.IsTamperProtected } else { $null })
      signatureAgeDays = [int]$mp.AntivirusSignatureAge }
  }
  @($out)
}

function Get-FirewallInventory {
  $profiles = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)
  if ($profiles.Count -eq 0) { return $null }
  $on = @($profiles | Where-Object { $_.Enabled } | ForEach-Object { $_.Name })
  @{ enabled = ($on.Count -eq $profiles.Count); detail = $(if ($on.Count) { "on: $($on -join ', ')" } else { 'all profiles off' }) }
}

# ---- Attack Reduction: hardening facts (graded by the platform; keys match contracts) --------
# A fact that cannot be read is left out, and the platform shows that check as "unknown".
function Get-RegValue([string]$Path, [string]$Name) {
  try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}
function Add-Fact([hashtable]$Facts, [string]$Name, [scriptblock]$Get) {
  try { $v = & $Get; if ($null -ne $v) { $Facts[$Name] = $v } } catch { }
}
function Get-HardeningFacts {
  $f = @{}
  $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
  $sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
  $smb = $null
  try { $smb = Get-SmbServerConfiguration -ErrorAction Stop } catch { }
  if ($smb) { $f.smb1_enabled = [bool]$smb.EnableSMB1Protocol; $f.smb_signing_required = [bool]$smb.RequireSecuritySignature }
  Add-Fact $f 'llmnr_disabled' { $v = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'; [bool]($null -ne $v -and [int]$v -eq 0) }
  Add-Fact $f 'netbios_enabled_adapters' { @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true' -ErrorAction Stop | Where-Object { $_.TcpipNetbiosOptions -ne 2 }).Count }
  $f.wdigest_use_logon_credential = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
  Add-Fact $f 'lsa_run_as_ppl' { $v = Get-RegValue $lsa 'RunAsPPL'; if ($null -eq $v) { 0 } else { [int]$v } }
  Add-Fact $f 'lm_compat_level' { $v = Get-RegValue $lsa 'LmCompatibilityLevel'; if ($null -eq $v) { 3 } else { [int]$v } }
  Add-Fact $f 'credential_guard_running' { $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop; [bool](@($dg.SecurityServicesRunning) -contains 1) }
  Add-Fact $f 'rdp_enabled' { $v = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'; [bool]($null -ne $v -and [int]$v -eq 0) }
  Add-Fact $f 'rdp_nla' { [int](Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication') -eq 1 }
  Add-Fact $f 'powershell_v2_enabled' { (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction Stop).State -eq 'Enabled' }
  Add-Fact $f 'ps_scriptblock_logging' { [int](Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging') -eq 1 }
  Add-Fact $f 'uac_enabled' { $v = Get-RegValue $sys 'EnableLUA'; ($null -eq $v) -or ([int]$v -eq 1) }
  Add-Fact $f 'uac_admin_prompt' { $v = Get-RegValue $sys 'ConsentPromptBehaviorAdmin'; if ($null -eq $v) { 5 } else { [int]$v } }
  Add-Fact $f 'autorun_disabled' { [int](Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun') -eq 255 }
  Add-Fact $f 'bitlocker_os_protected' { "$((Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop).ProtectionStatus)" -eq 'On' }
  Add-Fact $f 'asr_rules' {
    $mp = Get-MpPreference -ErrorAction Stop
    $ids = @($mp.AttackSurfaceReductionRules_Ids); $acts = @($mp.AttackSurfaceReductionRules_Actions); $pairs = @()
    for ($i = 0; $i -lt $ids.Count; $i++) { if ($ids[$i]) { $pairs += "$($ids[$i])=$($acts[$i])" } }
    $pairs -join ','
  }
  Add-Fact $f 'last_patch_days' {
    $last = Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($last) { [int]((Get-Date) - $last.InstalledOn).TotalDays }
  }
  $f
}

function Send-Inventory {
  $body = @{
    software = @(Get-InstalledSoftware); services = @(Get-ServiceInventory); users = @(Get-UserInventory)
    processes = @(Get-ProcessInventory); ports = @(Get-PortInventory); antivirus = @(Get-AntivirusInventory); firewall = Get-FirewallInventory
    hardening = Get-HardeningFacts
  }
  Invoke-RestMethod -Method Post -Uri "$($Conf.platformUrl)/api/v1/agent/inventory" -TimeoutSec 60 `
    -Headers @{ authorization = "Bearer $($Conf.agentToken)" } -ContentType 'application/json' -Body ([Text.Encoding]::UTF8.GetBytes(($body | ConvertTo-Json -Depth 5 -Compress)))
}
$InventoryEverySeconds = 1800

# ---- App Control -----------------------------------------------------------------------------
# Policy from GET /agent/app-control (JSON). Core OS processes and the agent itself are never
# stopped (keep in sync with PROTECTED_PROGRAMS in contracts).
$AcProtected = @('system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe', 'services.exe', 'lsass.exe', 'lsaiso.exe', 'svchost.exe',
  'explorer.exe', 'dwm.exe', 'fontdrvhost.exe', 'conhost.exe', 'powershell.exe', 'sciatagent.exe', 'msmpeng.exe', 'registry')
$AcPolicyFile = Join-Path $DataDir 'app-control.json'
$script:AcPolicy = $null
$script:AcSeen = @{}
$script:AcHash = @{}
$script:AcPublisher = @{}

function Sync-AppControl($Response) {
  $etag = "$($Response.appControlEtag)"
  if (-not $etag) { return }
  if ($script:AcPolicy -and $script:AcPolicy.etag -eq $etag) { return }
  if (-not $script:AcPolicy -and (Test-Path $AcPolicyFile)) {
    try { $script:AcPolicy = Get-Content $AcPolicyFile -Raw | ConvertFrom-Json } catch { }
    if ($script:AcPolicy -and $script:AcPolicy.etag -eq $etag) { return }
  }
  $p = Invoke-RestMethod -Method Get -Uri "$($Conf.platformUrl)/api/v1/agent/app-control" -TimeoutSec 20 -Headers @{ authorization = "Bearer $($Conf.agentToken)" }
  $p | ConvertTo-Json -Depth 4 | Set-Content -Path $AcPolicyFile -Encoding UTF8
  $script:AcPolicy = $p
  Write-AgentLog "App Control policy updated ($etag, mode $($p.mode))"
}

# Only * is a wildcard in rule values; -like is case-insensitive.
function Test-AcWildcard([string]$Pattern, [string]$Value) {
  if (-not $Value) { return $false }
  $escaped = [Management.Automation.WildcardPattern]::Escape($Pattern) -replace '`\*', '*'
  return $Value -like $escaped
}

function Get-AcHash([string]$Path) {
  try { $key = "$Path|$((Get-Item -LiteralPath $Path -ErrorAction Stop).LastWriteTimeUtc.Ticks)" } catch { return $null }
  if (-not $script:AcHash.ContainsKey($key)) { $script:AcHash[$key] = $(try { (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() } catch { $null }) }
  return $script:AcHash[$key]
}

function Get-AcPublisher([string]$Path) {
  if (-not $script:AcPublisher.ContainsKey($Path)) {
    $script:AcPublisher[$Path] = $(try {
      $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
      if ($sig.Status -eq 'Valid' -and $sig.SignerCertificate) { ($sig.SignerCertificate.Subject -split ',' | Where-Object { $_.Trim() -like 'CN=*' } | Select-Object -First 1).Trim().Substring(3) } else { $null }
    } catch { $null })
  }
  return $script:AcPublisher[$Path]
}

function Get-AcDecision([string]$Name, [string]$Path) {
  $block = $null
  foreach ($r in @($script:AcPolicy.rules)) {
    if ($r.platform -ne 'any' -and $r.platform -ne 'windows') { continue }
    $hit = switch ($r.kind) {
      'name' { (Test-AcWildcard $r.value $Name) -or ($Path -and (Test-AcWildcard $r.value (Split-Path -Leaf $Path))) }
      'path' { Test-AcWildcard $r.value $Path }
      'sha256' { $Path -and ((Get-AcHash $Path) -eq "$($r.value)".ToLowerInvariant()) }
      'publisher' { $Path -and (Test-AcWildcard $r.value (Get-AcPublisher $Path)) }
      default { $false }
    }
    if (-not $hit) { continue }
    if ($r.action -eq 'allow') { return @{ verdict = 'allow'; rule = $r.id } }
    if (-not $block) { $block = @{ verdict = 'block'; rule = $r.id } }
  }
  return $block
}

function Invoke-AppControl {
  $p = $script:AcPolicy
  if (-not $p -or $p.mode -eq 'off' -or @($p.rules).Count -eq 0) { return }
  $events = @()
  foreach ($proc in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) {
    $id = [int]$proc.ProcessId
    if ($id -le 4 -or $id -eq $PID) { continue }
    $name = "$($proc.Name)"
    if ($AcProtected -contains $name.ToLowerInvariant()) { continue }
    if ([int]$proc.ParentProcessId -eq $PID) { continue }   # the agent's own helpers
    $d = Get-AcDecision $name "$($proc.ExecutablePath)"
    if (-not $d -or $d.verdict -ne 'block') { continue }
    $key = "$id|$($proc.CreationDate)|$($p.mode)"
    if ($script:AcSeen.ContainsKey($key)) { continue }
    $script:AcSeen[$key] = $true
    $verdict = 'audited'
    if ($p.mode -eq 'enforce') { try { Stop-Process -Id $id -Force -ErrorAction Stop; $verdict = 'blocked' } catch { } }
    Write-AgentLog "App Control: $verdict $($proc.ExecutablePath) (pid $id, rule $($d.rule))" 'Warning'
    $e = @{ name = $name; ruleId = "$($d.rule)"; verdict = $verdict; occurredAt = (Get-Date).ToUniversalTime().ToString('s') + 'Z' }
    if ($proc.ExecutablePath) { $e.path = "$($proc.ExecutablePath)" }
    $events += $e
  }
  if ($script:AcSeen.Count -gt 5000) { $script:AcSeen = @{} }
  if ($events.Count -gt 0) {
    try { Invoke-Api '/agent/app-control/events' @{ events = @($events | Select-Object -First 200) } | Out-Null } catch { Write-AgentLog "could not report App Control events: $($_.Exception.Message)" 'Warning' }
  }
}

switch ($Command) {
  'once' { $r = Invoke-Checkin; $r | ConvertTo-Json -Compress -Depth 4; Invoke-Commands $r | Out-Null; try { Sync-AppControl $r; Invoke-AppControl } catch { Write-AgentLog "App Control: $($_.Exception.Message)" 'Warning' }; try { Send-Inventory | Out-Null } catch { Write-AgentLog "inventory upload failed: $($_.Exception.Message)" 'Warning' } }
  'inventory' { @{ software = @(Get-InstalledSoftware); services = @(Get-ServiceInventory); users = @(Get-UserInventory); processes = @(Get-ProcessInventory); ports = @(Get-PortInventory); antivirus = @(Get-AntivirusInventory); firewall = Get-FirewallInventory; hardening = Get-HardeningFacts } | ConvertTo-Json -Depth 5 }
  'status' {
    "SCIAT Agent $AgentVersion"
    "platform: $($Conf.platformUrl)"
    $last = Join-Path $DataDir 'last-checkin'
    if (Test-Path $last) { "last check-in: $(Get-Content $last)" } else { 'last check-in: never' }
  }
  'run' {
    Write-AgentLog "SCIAT Agent $AgentVersion starting (platform $($Conf.platformUrl))"
    $failures = 0
    $lastInventory = [datetime]::MinValue
    while ($true) {
      try {
        $resp = Invoke-Checkin
        $failures = 0
        (Get-Date).ToUniversalTime().ToString('s') + 'Z' | Set-Content -Path (Join-Path $DataDir 'last-checkin') -Encoding ascii
        $delay = if ($resp.pollSeconds) { [int]$resp.pollSeconds } else { 60 }
        # Ran a command: check in again soon so the platform sees the new state.
        if (Invoke-Commands $resp) { $delay = 5 }
        try { Sync-AppControl $resp } catch { Write-AgentLog "App Control policy download failed: $($_.Exception.Message)" 'Warning' }
        if (((Get-Date) - $lastInventory).TotalSeconds -ge $InventoryEverySeconds) {
          try { Send-Inventory | Out-Null; $lastInventory = Get-Date }
          catch { Write-AgentLog "inventory upload failed: $($_.Exception.Message)" 'Warning'; $lastInventory = (Get-Date).AddSeconds(300 - $InventoryEverySeconds) }
        }
      } catch {
        $failures++
        # Back off while the platform is unreachable (max 10 minutes).
        $delay = 60 * [Math]::Min($failures, 10)
        if ($failures % 5 -eq 1) { Write-AgentLog "check-in failed ($failures in a row): $($_.Exception.Message)" 'Warning' }
      }
      # Sleep in 10-second slices, applying App Control between them.
      $until = (Get-Date).AddSeconds($delay)
      while ((Get-Date) -lt $until) {
        try { Invoke-AppControl } catch { Write-AgentLog "App Control: $($_.Exception.Message)" 'Warning' }
        Start-Sleep -Seconds ([Math]::Max(1, [Math]::Min(10, [int]($until - (Get-Date)).TotalSeconds)))
      }
    }
  }
}
