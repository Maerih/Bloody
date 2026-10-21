//go:build !windows

package host

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Platform is the platform name the API expects.
func Platform() string {
	if runtime.GOOS == "darwin" {
		return "macos"
	}
	return "linux"
}

// OSName, e.g. "Ubuntu 24.04.1 LTS" or "macOS 15.1".
func OSName() string {
	if runtime.GOOS == "darwin" {
		v, _ := exec.Command("sw_vers", "-productVersion").Output()
		return strings.TrimSpace("macOS " + strings.TrimSpace(string(v)))
	}
	f, err := os.Open("/etc/os-release")
	if err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if v, ok := strings.CutPrefix(sc.Text(), "PRETTY_NAME="); ok {
				return strings.Trim(v, `"'`)
			}
		}
	}
	return "Linux"
}

// UptimeSeconds since boot.
func UptimeSeconds() int64 {
	if raw, err := os.ReadFile("/proc/uptime"); err == nil {
		if f, err := strconv.ParseFloat(strings.Fields(string(raw))[0], 64); err == nil {
			return int64(f)
		}
	}
	return 0
}

// MachineID identifies the computer across reinstalls (systemd machine-id).
func MachineID() string {
	raw, _ := os.ReadFile("/etc/machine-id")
	return strings.TrimSpace(string(raw))
}

// DNSServers the computer resolves with.
func DNSServers() []string {
	var all []string
	if raw, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		for _, l := range strings.Split(string(raw), "\n") {
			if f := strings.Fields(l); len(f) >= 2 && f[0] == "nameserver" {
				all = append(all, f[1])
			}
		}
	}
	// systemd-resolved: resolv.conf only lists the 127.0.0.53 stub.
	if _, err := exec.LookPath("resolvectl"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if out, err := exec.CommandContext(ctx, "resolvectl", "dns").Output(); err == nil {
			for _, l := range strings.Split(string(out), "\n") {
				if _, rest, ok := strings.Cut(l, ":"); ok {
					all = append(all, strings.Fields(rest)...)
				}
			}
		}
	}
	return onlyIPs(all)
}

// Engines reports the security tools found on the computer and whether they run.
func Engines() map[string]string {
	out := map[string]string{}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return out
	}
	for _, svc := range []string{"wazuh-agent", "osqueryd", "falcon-sensor", "velociraptor_client"} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		state, _ := exec.CommandContext(ctx, "systemctl", "is-active", svc+".service").Output()
		cancel()
		s := strings.TrimSpace(string(state))
		if s != "" && s != "inactive" && s != "unknown" {
			out[svc] = s
		} else if s == "inactive" {
			if _, err := os.Stat("/etc/systemd/system/" + svc + ".service"); err == nil {
				out[svc] = s
			} else if _, err := os.Stat("/lib/systemd/system/" + svc + ".service"); err == nil {
				out[svc] = s
			}
		}
	}
	return out
}
