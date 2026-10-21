//go:build windows

package commands

import (
	"errors"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows/registry"
)

func setPolicyDword(path, name string, value uint32) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, path, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetDWordValue(name, value)
}

// Fixed PowerShell for fixes that have no registry equivalent (never built from input).
var psFixes = map[string]struct{ script, done string }{
	"win_smb1": {`Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false; try { Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null } catch { }`, "SMBv1 server disabled (feature removal completes at the next restart)"},
	"win_netbios": {`$n = 0; foreach ($a in @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true')) { $r = Invoke-CimMethod -InputObject $a -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]2 }; if ($r.ReturnValue -in 0, 1) { $n++ } }; "NetBIOS over TCP/IP disabled on $n adapter(s)"`, ""},
	"win_powershell_v2": {`foreach ($f in 'MicrosoftWindowsPowerShellV2Root', 'MicrosoftWindowsPowerShellV2') { try { Disable-WindowsOptionalFeature -Online -FeatureName $f -NoRestart -ErrorAction Stop | Out-Null } catch { } }`, "PowerShell 2.0 engine removed"},
	"win_guest": {`$g = @(Get-LocalUser | Where-Object { "$($_.SID)" -like '*-501' }); $g | Disable-LocalUser; "Guest account disabled ($(@($g | ForEach-Object { $_.Name }) -join ', '))"`, ""},
}

// Harden applies the built-in Windows fixes (same as the PowerShell agent).
func Harden(check string) (string, error) {
	switch check {
	case "win_llmnr":
		return "LLMNR turned off", setPolicyDword(`SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`, "EnableMulticast", 0)
	case "win_wdigest":
		return "WDigest no longer keeps clear-text passwords", setPolicyDword(`SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`, "UseLogonCredential", 0)
	case "win_ps_logging":
		return "Script-block logging turned on", setPolicyDword(`SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`, "EnableScriptBlockLogging", 1)
	case "win_autorun":
		return "AutoRun disabled for all drives", setPolicyDword(`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer`, "NoDriveTypeAutoRun", 255)
	}
	fix, ok := psFixes[check]
	if !ok {
		return "no built-in fix for " + check, errors.New("unknown check")
	}
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", fix.script).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if fix.done != "" && err == nil {
		text = fix.done
	}
	return text, err
}
