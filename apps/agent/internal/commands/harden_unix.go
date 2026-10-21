//go:build !windows

package commands

import (
	"errors"
	"os"
	"os/exec"
	"runtime"
)

// Harden applies the built-in Linux / macOS fixes (same as the shell agent).
func Harden(check string) (string, error) {
	run := func(name string, args ...string) error { return exec.Command(name, args...).Run() }
	switch check {
	case "linux_aslr":
		if runtime.GOOS != "linux" {
			return "not a Linux endpoint", errors.New("wrong platform")
		}
		if err := os.WriteFile("/etc/sysctl.d/60-sciat-aslr.conf", []byte("kernel.randomize_va_space = 2\n"), 0o644); err != nil {
			return "", err
		}
		if err := run("sysctl", "-q", "-w", "kernel.randomize_va_space=2"); err != nil {
			return "", err
		}
		return "ASLR set to full (2)", nil
	case "mac_gatekeeper":
		if runtime.GOOS != "darwin" {
			return "not a macOS endpoint", errors.New("wrong platform")
		}
		if run("spctl", "--master-enable") != nil {
			if err := run("spctl", "--global-enable"); err != nil {
				return "", err
			}
		}
		return "Gatekeeper enabled", nil
	case "mac_guest":
		if runtime.GOOS != "darwin" {
			return "not a macOS endpoint", errors.New("wrong platform")
		}
		return "Guest user disabled", run("defaults", "write", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled", "-bool", "false")
	case "mac_auto_updates":
		if runtime.GOOS != "darwin" {
			return "not a macOS endpoint", errors.New("wrong platform")
		}
		if err := run("defaults", "write", "/Library/Preferences/com.apple.SoftwareUpdate", "CriticalUpdateInstall", "-bool", "true"); err != nil {
			return "", err
		}
		return "Security responses and system data files install automatically", run("defaults", "write", "/Library/Preferences/com.apple.SoftwareUpdate", "ConfigDataInstall", "-bool", "true")
	}
	return "no built-in fix for " + check, errors.New("unknown check")
}
