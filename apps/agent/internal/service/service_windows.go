//go:build windows

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// ServiceName is shared with the script agent's service, which the native one replaces.
const ServiceName = "SCIATAgent"

// BinaryName of the native agent inside Home.
const BinaryName = "sciat-agent.exe"

// Home is where the agent is installed.
func Home() string {
	if h := os.Getenv("SCIAT_AGENT_HOME"); h != "" {
		return h
	}
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, "SCIAT", "Agent")
}

// Helpers for this platform.
func Helpers() []HelperFile {
	return []HelperFile{{Served: "bloody-isolate.ps1", Local: "bloody-isolate.ps1", Mode: 0o644}, {Served: "sciat-agent.ps1", Local: "sciat-agent.ps1", Mode: 0o644}}
}

func removeExisting(m *mgr.Mgr) {
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return
	}
	_, _ = s.Control(svc.Stop)
	for i := 0; i < 20; i++ {
		if st, err := s.Query(); err != nil || st.State == svc.Stopped {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	_ = s.Delete()
	s.Close()
	time.Sleep(time.Second)
}

// Install copies the agent into Program Files and registers it as the "SCIAT Agent" service
// (automatic start, restarted on failure), replacing the script agent's service.
func Install(ctx context.Context, platformURL string) error {
	m, err := mgr.Connect()
	if err != nil {
		return errors.New("run the installer as Administrator")
	}
	defer m.Disconnect()
	if err := os.MkdirAll(Home(), 0o755); err != nil {
		return err
	}
	if err := FetchHelpers(ctx, platformURL, Home(), Helpers()); err != nil {
		return err
	}
	removeExisting(m)
	bin := filepath.Join(Home(), BinaryName)
	if err := CopySelf(bin); err != nil {
		return err
	}
	// Only SYSTEM and Administrators may change the agent's files.
	_ = exec.CommandContext(ctx, "icacls.exe", Home(), "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "/T", "/C", "/Q").Run()
	s, err := m.CreateService(ServiceName, bin, mgr.Config{
		DisplayName:  "SCIAT Agent",
		Description:  "SCIAT AFRICA endpoint agent: security monitoring and response.",
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
	}, "run-service")
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 10 * time.Second}, {Type: mgr.ServiceRestart, Delay: 30 * time.Second}, {Type: mgr.ServiceRestart, Delay: time.Minute}}, 86400)
	return s.Start()
}

// Uninstall releases isolation, removes the service, the agent and its configuration.
func Uninstall(ctx context.Context, confDir string) error {
	m, err := mgr.Connect()
	if err != nil {
		return errors.New("run as Administrator")
	}
	defer m.Disconnect()
	if iso := filepath.Join(Home(), "bloody-isolate.ps1"); fileExists(iso) {
		_ = exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", iso, "release").Run()
	}
	removeExisting(m)
	_ = os.RemoveAll(confDir)
	// The running executable cannot delete itself: schedule the folder for removal.
	return exec.Command("cmd.exe", "/c", "ping", "-n", "3", "127.0.0.1", ">", "nul", "&", "rmdir", "/s", "/q", Home()).Start()
}

type handler struct{ run func(ctx context.Context) }

func (h handler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.run(ctx); close(done) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(20 * time.Second):
				}
				return false, 0
			}
		case <-done:
			cancel()
			return false, 0
		}
	}
}

// RunService runs under the Service Control Manager (or in the foreground from a console).
func RunService(run func(ctx context.Context)) error {
	if is, err := svc.IsWindowsService(); err == nil && is {
		return svc.Run(ServiceName, handler{run: run})
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	run(ctx)
	return nil
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }
