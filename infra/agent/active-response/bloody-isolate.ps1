# SPDX-License-Identifier: LicenseRef-Bloody-Proprietary
# Copyright (c) 2026 Bloody. All rights reserved.
#
# bloody-isolate.ps1 - Bloody endpoint network isolation for Windows (Windows Defender Firewall).
#
#   lan   block the local network (RFC1918, CGNAT, link-local, IPv6 ULA/link-local); internet stays.
#   full  block everything except the Bloody platform / engine manager.
# Both modes keep the management path open so the endpoint can be released from the platform.
#
# Windows Firewall evaluates BLOCK rules before ALLOW rules, so exceptions cannot be "allowed back".
# The platform therefore sends precomputed block ranges (block4= / block6=) that already exclude the
# management and DNS addresses, loopback and DHCP broadcast.
#
# Usage:  bloody-isolate.ps1 isolate <lan|full> allow=<ips> [dns=<ips>] block4=<ranges> [block6=<ranges>]
#         bloody-isolate.ps1 release | status
# As a Wazuh active response the words arrive in parameters.extra_args of the JSON on stdin
# (bloody-isolate.cmd wraps this script).
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Words)
$ErrorActionPreference = 'Stop'
$Group = 'Bloody Isolation'
$StateFile = Join-Path $env:ProgramData 'Bloody\isolation.state'

function Write-Log([string]$Message) {
  try { Write-EventLog -LogName Application -Source 'Bloody' -EventId 4100 -Message $Message -ErrorAction Stop } catch { }
  [Console]::Error.WriteLine("bloody-isolate: $Message")
}
function Fail([string]$Message) { Write-Log "error: $Message"; exit 1 }

$EntryRe = '^([0-9]{1,3}(\.[0-9]{1,3}){3}|[0-9A-Fa-f:]+:[0-9A-Fa-f:]*)(/[0-9]{1,3})?$'
$RangeRe = '^([0-9]{1,3}(\.[0-9]{1,3}){3}|[0-9A-Fa-f:]+)(-([0-9]{1,3}(\.[0-9]{1,3}){3}|[0-9A-Fa-f:]+))?$'

function Split-List([string]$Csv, [string]$Pattern, [string]$Field) {
  $items = @($Csv -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
  foreach ($i in $items) { if ($i -notmatch $Pattern) { Fail "invalid $Field entry '$i'" } }
  return ,$items
}

function Remove-Isolation {
  Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue | Remove-NetFirewallRule
  if (Test-Path $StateFile) { Remove-Item $StateFile -Force }
}

function Invoke-Isolate([string[]]$Args2) {
  $mode = $Args2[0]
  if ($mode -ne 'lan' -and $mode -ne 'full') { Fail "mode must be 'lan' or 'full'" }
  $allow = @(); $block4 = @(); $block6 = @()
  foreach ($kv in $Args2[1..($Args2.Length - 1)]) {
    if ($kv -like 'allow=*') { $allow = Split-List $kv.Substring(6) $EntryRe 'allow' }
    elseif ($kv -like 'dns=*') { $null = Split-List $kv.Substring(4) $EntryRe 'dns' }
    elseif ($kv -like 'block4=*') { $block4 = Split-List $kv.Substring(7) $RangeRe 'block4' }
    elseif ($kv -like 'block6=*') { $block6 = Split-List $kv.Substring(7) $RangeRe 'block6' }
    else { Fail "unknown argument '$kv'" }
  }
  if ($allow.Count -eq 0) { Fail 'allow= must list the platform/manager addresses (otherwise the endpoint could never be released)' }
  if ($block4.Count -eq 0) { Fail 'block4= ranges are required (sent by the Bloody platform)' }
  $remote = @($block4 + $block6)
  # Replace atomically from the operator's point of view: remove old rules, then add both directions.
  Remove-Isolation
  foreach ($dir in 'Inbound', 'Outbound') {
    New-NetFirewallRule -DisplayName "Bloody isolation ($mode, $dir)" -Group $Group -Direction $dir -Action Block `
      -RemoteAddress $remote -Profile Any -Enabled True | Out-Null
  }
  New-Item -ItemType Directory -Force -Path (Split-Path $StateFile) | Out-Null
  "mode=$mode`nallow=$($allow -join ',')`nsince=$((Get-Date).ToUniversalTime().ToString('s'))Z" | Set-Content -Path $StateFile -Encoding ascii
  Write-Log "isolated (mode=$mode, management=$($allow -join ','))"
}

if (-not $Words -or $Words.Count -eq 0) {
  # Wazuh active response: one JSON line on stdin.
  $line = [Console]::In.ReadLine()
  if ($line) {
    $msg = $line | ConvertFrom-Json
    $Words = @($msg.parameters.extra_args)
    if ($msg.command -eq 'delete') { $Words = @('release') }
  }
}

switch ($Words[0]) {
  'isolate' { Invoke-Isolate $Words[1..($Words.Length - 1)] }
  'release' { Remove-Isolation; Write-Log 'released' }
  'status'  { if (Test-Path $StateFile) { 'isolated'; Get-Content $StateFile } else { 'not isolated' } }
  default   { Fail 'usage: bloody-isolate.ps1 isolate <lan|full> allow=<ips> block4=<ranges> [block6=<ranges>] [dns=<ips>] | release | status' }
}
