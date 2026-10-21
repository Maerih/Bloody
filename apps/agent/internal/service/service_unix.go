//go:build !windows

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// Home is where the agent is installed.
func Home() string {
	if h := os.Getenv("SCIAT_AGENT_HOME"); h != "" {
		return h
	}
	return "/opt/sciat-agent"
}

// BinaryName of the native agent inside Home.
const BinaryName = "sciat-agentd"

const unitPath = "/etc/systemd/system/sciat-agent.service"

// Helpers for this platform.
func Helpers() []HelperFile {
	iso := "bloody-isolate"
	if runtime.GOOS == "darwin" {
		iso = "bloody-isolate-macos"
	}
	return []HelperFile{{Served: iso, Local: "bloody-isolate", Mode: 0o750}, {Served: "sciat-agent.sh", Local: "sciat-agent", Mode: 0o750}}
}

// Install copies the agent into place and starts it with systemd (replacing the shell agent's
// unit of the same name).
func Install(ctx context.Context, platformURL string) error {
	if runtime.GOOS != "linux" {
		return errors.New("service install is implemented for Linux (systemd) and Windows")
	}
	if os.Geteuid() != 0 {
		return errors.New("run the installer as root (sudo)")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return errors.New("systemd is required: start '" + filepath.Join(Home(), BinaryName) + " run' from your init system instead")
	}
	if err := os.MkdirAll(Home(), 0o755); err != nil {
		return err
	}
	if err := FetchHelpers(ctx, platformURL, Home(), Helpers()); err != nil {
		return err
	}
	bin := filepath.Join(Home(), BinaryName)
	if err := CopySelf(bin); err != nil {
		return err
	}
	unit := fmt.Sprintf(`[Unit]
Description=SCIAT Agent
Documentation=https://sciat.africa
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s run
Restart=always
RestartSec=10
# The agent must run as root: isolation edits the firewall, collectors read system state.
User=root
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
`, bin)
	if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
		return err
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", "sciat-agent.service"}, {"restart", "sciat-agent.service"}} {
		if out, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl %v: %v: %s", args, err, out)
		}
	}
	return nil
}

// Uninstall stops the service and removes the agent, its configuration and helpers. The
// computer is released from isolation first.
func Uninstall(ctx context.Context, confDir string) error {
	if os.Geteuid() != 0 {
		return errors.New("run as root (sudo)")
	}
	if iso := filepath.Join(Home(), "bloody-isolate"); fileExists(iso) {
		_ = exec.CommandContext(ctx, iso, "release").Run()
	}
	_ = exec.CommandContext(ctx, "systemctl", "disable", "--now", "sciat-agent.service").Run()
	_ = os.Remove(unitPath)
	_ = exec.CommandContext(ctx, "systemctl", "daemon-reload").Run()
	if err := os.RemoveAll(Home()); err != nil {
		return err
	}
	return os.RemoveAll(confDir)
}

// RunService runs the agent in the foreground (systemd supervises it).
func RunService(run func(ctx context.Context)) error {
	ctx, stop := signalContext()
	defer stop()
	run(ctx)
	return nil
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }
