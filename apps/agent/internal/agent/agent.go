// Package agent is the check-in loop: report liveness and host facts, run queued commands,
// send the host inventory every 30 minutes.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"time"

	"sciat.africa/agent/internal/api"
	"sciat.africa/agent/internal/commands"
	"sciat.africa/agent/internal/config"
	"sciat.africa/agent/internal/host"
	"sciat.africa/agent/internal/isolation"
)

// InventoryEvery is how often the host inventory is sent.
const InventoryEvery = 30 * time.Minute

// Agent is one enrolled computer.
type Agent struct {
	Cfg      config.Config
	Home     string // where the agent and its helpers are installed
	StateDir string // configuration and cached state
	Version  string
	Log      *log.Logger

	client        *api.Client
	runner        commands.Runner
	isolated      atomic.Bool
	lastInventory time.Time
	platformHost  string
}

// New prepares an agent from its configuration.
func New(cfg config.Config, home, stateDir, version string, logger *log.Logger) *Agent {
	a := &Agent{Cfg: cfg, Home: home, StateDir: stateDir, Version: version, Log: logger}
	if u, err := url.Parse(cfg.PlatformURL); err == nil {
		a.platformHost = u.Hostname()
	}
	// While isolated, connect to the cached platform address (DNS may be blocked).
	a.client = api.New(cfg.PlatformURL, cfg.AgentToken, func() string {
		if !a.isolated.Load() {
			return ""
		}
		if ips := host.CachedPlatformIPs(stateDir); len(ips) > 0 {
			return ips[0]
		}
		return ""
	})
	a.runner = commands.Runner{Isolation: isolation.Helper{Home: home}, Harden: commands.Harden}
	return a
}

// Checkin sends one heartbeat and returns the platform's answer.
func (a *Agent) Checkin(ctx context.Context) (api.HeartbeatResponse, error) {
	state, mode := a.runner.Isolation.Status()
	a.isolated.Store(state == "isolated")
	req := api.HeartbeatRequest{
		Hostname:      host.Hostname(),
		OS:            host.OSName(),
		Version:       a.Version,
		IPs:           nonNil(host.IPs()),
		UptimeSeconds: host.UptimeSeconds(),
		Isolation:     api.Isolation{State: state, Mode: mode},
		Engines:       host.Engines(),
		PlatformIPs:   nonNil(host.PlatformIPs(a.platformHost, a.StateDir)),
		DNSServers:    nonNil(host.DNSServers()),
	}
	var res api.HeartbeatResponse
	err := a.client.Post(ctx, "/agent/heartbeat", req, &res)
	if err == nil {
		_ = os.WriteFile(filepath.Join(a.StateDir, "last-checkin"), []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o600)
	}
	return res, err
}

// RunCommands executes the queued commands and reports each result. It returns true when any ran.
func (a *Agent) RunCommands(ctx context.Context, cmds []api.Command) bool {
	ran := false
	for _, c := range cmds {
		if !commands.ValidID(c.ID) {
			continue
		}
		r := a.runner.Run(c.Args)
		status := "failed"
		if r.OK {
			status = "succeeded"
		}
		verb := "?"
		if len(c.Args) > 0 {
			verb = c.Args[0]
		}
		a.Log.Printf("command %s (%s): %s", verb, c.ID, status)
		out := r.Output
		if len(out) > 4000 {
			out = out[:4000]
		}
		if err := a.client.Post(ctx, "/agent/commands/"+c.ID+"/result", api.CommandResult{Status: status, Output: out}, nil); err != nil {
			a.Log.Printf("could not report command %s: %v", c.ID, err)
		}
		if r.Reinventory {
			a.lastInventory = time.Time{}
		}
		ran = true
	}
	return ran
}

// collectorCommand runs the script collectors installed with the agent ("inventory" mode), until
// every collector is native.
func (a *Agent) collectorCommand(ctx context.Context) (*exec.Cmd, error) {
	if runtime.GOOS == "windows" {
		script := filepath.Join(a.Home, "sciat-agent.ps1")
		if _, err := os.Stat(script); err != nil {
			return nil, errors.New("inventory collectors are not installed")
		}
		return exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script, "inventory"), nil
	}
	script := filepath.Join(a.Home, "sciat-agent") // the shell agent, installed beside the native one
	if _, err := os.Stat(script); err != nil {
		return nil, errors.New("inventory collectors are not installed")
	}
	cmd := exec.CommandContext(ctx, "/bin/bash", script, "inventory")
	cmd.Env = append(os.Environ(), "SCIAT_AGENT_HOME="+a.Home, "SCIAT_AGENT_CONF="+filepath.Join(a.StateDir, "agent.conf"))
	return cmd, nil
}

// SendInventory collects and uploads the host inventory.
func (a *Agent) SendInventory(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	cmd, err := a.collectorCommand(ctx)
	if err != nil {
		return err
	}
	out, err := cmd.Output()
	if err != nil {
		return err
	}
	if !json.Valid(out) {
		return errors.New("the inventory collectors returned invalid JSON")
	}
	return a.client.Post(ctx, "/agent/inventory", json.RawMessage(out), nil)
}

// Once is one full cycle; it returns how long to wait before the next one.
func (a *Agent) Once(ctx context.Context) (time.Duration, error) {
	res, err := a.Checkin(ctx)
	if err != nil {
		return 0, err
	}
	delay := time.Duration(res.PollSeconds) * time.Second
	if delay < 10*time.Second || delay > time.Hour {
		delay = 60 * time.Second
	}
	if a.RunCommands(ctx, res.Commands) {
		delay = 5 * time.Second
	}
	if time.Since(a.lastInventory) >= InventoryEvery {
		if err := a.SendInventory(ctx); err != nil {
			a.Log.Printf("inventory upload failed: %v", err)
			// Try again in 5 minutes rather than waiting a whole interval.
			a.lastInventory = time.Now().Add(-InventoryEvery + 5*time.Minute)
		} else {
			a.lastInventory = time.Now()
		}
	}
	return delay, nil
}

// Run checks in until ctx is cancelled, backing off while the platform is unreachable.
func (a *Agent) Run(ctx context.Context) {
	a.Log.Printf("SCIAT Agent %s starting (platform %s)", a.Version, a.Cfg.PlatformURL)
	failures := 0
	for {
		delay, err := a.Once(ctx)
		if err != nil {
			failures++
			var he *api.HTTPError
			if errors.As(err, &he) && he.Status == 401 {
				a.Log.Printf("the platform refused this agent's token: reinstall the agent with a current account key")
			}
			if failures%5 == 1 {
				a.Log.Printf("check-in failed (%d in a row): %v", failures, err)
			}
			delay = time.Duration(min(failures, 10)) * time.Minute
			if errors.As(err, &he) && he.RetryAfter > delay {
				delay = he.RetryAfter
			}
		} else {
			failures = 0
		}
		select {
		case <-ctx.Done():
			a.Log.Printf("SCIAT Agent stopping")
			return
		case <-time.After(delay):
		}
	}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
