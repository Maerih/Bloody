// SCIAT Agent (native) — proprietary, (c) SCIAT AFRICA.
//
//	sciat-agent install --url https://soc.example.com --account-key sak_… --org-key acme
//	sciat-agent status | once | run | uninstall | version
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"sciat.africa/agent/internal/agent"
	"sciat.africa/agent/internal/api"
	"sciat.africa/agent/internal/config"
	"sciat.africa/agent/internal/host"
	"sciat.africa/agent/internal/isolation"
	"sciat.africa/agent/internal/service"
)

// version is set at build time (-ldflags "-X main.version=…").
var version = "2.0.0-dev"

const usage = `SCIAT Agent %s (%s/%s)

Usage:
  sciat-agent install --url <platform URL> --account-key <key> --org-key <organization key> [--reenroll]
  sciat-agent status       show enrollment, last check-in and isolation
  sciat-agent once         check in once, run queued commands, send the inventory
  sciat-agent run          run in the foreground (what the service runs)
  sciat-agent uninstall    release isolation and remove the agent
  sciat-agent version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usage, version, runtime.GOOS, runtime.GOARCH)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "install":
		err = install(os.Args[2:])
	case "run", "run-service":
		err = run()
	case "once":
		err = once()
	case "status":
		err = status()
	case "uninstall":
		err = service.Uninstall(context.Background(), config.Dir())
		if err == nil {
			fmt.Println("SCIAT Agent removed.")
		}
	case "version", "--version", "-v":
		fmt.Printf("SCIAT Agent %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
	default:
		fmt.Fprintf(os.Stderr, usage, version, runtime.GOOS, runtime.GOARCH)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sciat-agent:", err)
		os.Exit(1)
	}
}

func install(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	platformURL := fs.String("url", os.Getenv("SCIAT_PLATFORM_URL"), "platform URL, e.g. https://soc.example.com")
	accountKey := fs.String("account-key", os.Getenv("SCIAT_ACCOUNT_KEY"), "account key (Download Agent page)")
	orgKey := fs.String("org-key", os.Getenv("SCIAT_ORG_KEY"), "organization key")
	reenroll := fs.Bool("reenroll", false, "enroll again even if this computer is already enrolled")
	if err := fs.Parse(args); err != nil {
		return err
	}
	*platformURL = strings.TrimRight(strings.TrimSpace(*platformURL), "/")
	cfgPath := config.Path()
	if existing, err := config.Load(cfgPath); err == nil && !*reenroll && (*platformURL == "" || existing.PlatformURL == *platformURL) {
		// Upgrading (e.g. from the script agent): keep the computer's identity and token.
		fmt.Printf("Already enrolled with %s; keeping the enrollment.\n", existing.PlatformURL)
		*platformURL = existing.PlatformURL
	} else {
		if *platformURL == "" || *accountKey == "" || *orgKey == "" {
			return errors.New("--url, --account-key and --org-key are required (copy them from Download Agent in the SCIAT Command Center)")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		fmt.Printf("Enrolling %s with %s…\n", host.Hostname(), *platformURL)
		res, err := api.Enroll(ctx, *platformURL, api.EnrollRequest{
			AccountKey: *accountKey, OrganizationKey: *orgKey, Hostname: host.Hostname(), Platform: host.Platform(),
			OS: host.OSName(), Version: version, IPs: host.IPs(), MachineID: host.MachineID(),
		})
		if err != nil {
			return fmt.Errorf("enrollment failed: %w", err)
		}
		if err := config.Save(cfgPath, config.Config{PlatformURL: *platformURL, AgentToken: res.Token}); err != nil {
			return err
		}
		fmt.Printf("Enrolled (agent %s).\n", res.AgentID)
	}
	fmt.Println("Installing helpers:")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := service.Install(ctx, *platformURL); err != nil {
		return err
	}
	fmt.Printf("SCIAT Agent %s installed and running.\n", version)
	return nil
}

func load() (config.Config, error) {
	cfg, err := config.Load(config.Path())
	if err != nil {
		return cfg, fmt.Errorf("not enrolled (%v): run 'sciat-agent install' first", err)
	}
	return cfg, nil
}

// logger writes to stderr (journald on Linux) or, under the Windows service, to agent.log in the
// data folder (rotated at 5 MB).
func logger() *log.Logger {
	var w io.Writer = os.Stderr
	if runtime.GOOS == "windows" {
		p := filepath.Join(config.Dir(), "agent.log")
		if st, err := os.Stat(p); err == nil && st.Size() > 5<<20 {
			_ = os.Rename(p, p+".1")
		}
		if f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
			w = io.MultiWriter(f, os.Stderr)
		}
	}
	return log.New(w, "", log.LstdFlags|log.LUTC)
}

func run() error {
	cfg, err := load()
	if err != nil {
		return err
	}
	a := agent.New(cfg, service.Home(), config.Dir(), version, logger())
	return service.RunService(a.Run)
}

func once() error {
	cfg, err := load()
	if err != nil {
		return err
	}
	a := agent.New(cfg, service.Home(), config.Dir(), version, log.New(os.Stderr, "", log.LstdFlags))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	res, err := a.Checkin(ctx)
	if err != nil {
		return err
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(out))
	a.RunCommands(ctx, res.Commands)
	if err := a.SendInventory(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "inventory upload failed:", err)
	}
	return nil
}

func status() error {
	fmt.Printf("SCIAT Agent %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
	cfg, err := load()
	if err != nil {
		return err
	}
	fmt.Println("platform:", cfg.PlatformURL)
	if raw, err := os.ReadFile(filepath.Join(config.Dir(), "last-checkin")); err == nil {
		fmt.Println("last check-in:", strings.TrimSpace(string(raw)))
	} else {
		fmt.Println("last check-in: never")
	}
	state, mode := isolation.Helper{Home: service.Home()}.Status()
	if mode != "" {
		state += " (" + mode + ")"
	}
	fmt.Println("isolation:", state)
	return nil
}
