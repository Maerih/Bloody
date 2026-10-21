//go:build windows

package host

import (
	"fmt"
	"os/exec"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"
)

// Platform is the platform name the API expects.
func Platform() string { return "windows" }

// OSName, e.g. "Microsoft Windows 11 Pro 10.0.26200" (the same text as Win32_OperatingSystem).
func OSName() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return "Microsoft Windows"
	}
	defer k.Close()
	product, _, _ := k.GetStringValue("ProductName")
	build, _, _ := k.GetStringValue("CurrentBuildNumber")
	// The registry still says "Windows 10" on Windows 11 (build 22000 and later).
	var n int
	fmt.Sscanf(build, "%d", &n)
	if n >= 22000 {
		product = strings.Replace(product, "Windows 10", "Windows 11", 1)
	}
	if !strings.HasPrefix(product, "Microsoft ") {
		product = "Microsoft " + product
	}
	return fmt.Sprintf("%s 10.0.%s", product, build)
}

// UptimeSeconds since boot.
func UptimeSeconds() int64 {
	return int64(windows.DurationSinceBoot().Seconds())
}

// MachineID is the SMBIOS UUID, as the Windows installer sends it.
func MachineID() string {
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "(Get-CimInstance Win32_ComputerSystemProduct).UUID").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// DNSServers configured on the network adapters that are up.
func DNSServers() []string {
	size := uint32(15000)
	for i := 0; i < 3; i++ {
		buf := make([]byte, size)
		aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST, 0, aa, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return nil
		}
		var all []string
		for a := aa; a != nil; a = a.Next {
			if a.OperStatus != windows.IfOperStatusUp {
				continue
			}
			for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
				all = append(all, d.Address.IP().String())
			}
		}
		return onlyIPs(all)
	}
	return nil
}

// Engines reports the security tools found on the computer and whether they run.
func Engines() map[string]string {
	out := map[string]string{}
	m, err := mgr.Connect()
	if err != nil {
		return out
	}
	defer m.Disconnect()
	for _, name := range []string{"WazuhSvc", "osqueryd", "Velociraptor", "Sysmon64", "WinDefend"} {
		s, err := m.OpenService(name)
		if err != nil {
			continue
		}
		st, err := s.Query()
		s.Close()
		if err != nil {
			continue
		}
		switch st.State {
		case 4: // SERVICE_RUNNING
			out[name] = "running"
		case 1:
			out[name] = "stopped"
		default:
			out[name] = "pending"
		}
	}
	return out
}
