// Package config reads and writes the SCIAT Agent configuration in the same files and formats as
// the script agents, so the native agent installs over them without enrolling again:
//
//	Linux / macOS  /etc/sciat-agent/agent.conf            PLATFORM_URL='…' / AGENT_TOKEN='…'
//	Windows        %ProgramData%\SCIAT\Agent\agent.json   {"platformUrl": "…", "agentToken": "…"}
package config

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Config is what the agent needs to talk to the platform.
type Config struct {
	PlatformURL string `json:"platformUrl"`
	AgentToken  string `json:"agentToken"`
}

// Validate checks the values look like what the platform issues.
func (c Config) Validate() error {
	u, err := url.Parse(c.PlatformURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("platform URL %q is not an http(s) URL", c.PlatformURL)
	}
	if !strings.HasPrefix(c.AgentToken, "sat_") {
		return errors.New("agent token is missing or malformed")
	}
	return nil
}

// Dir is where the configuration and the agent's state (cached platform addresses…) live.
func Dir() string {
	if d := os.Getenv("SCIAT_AGENT_CONF_DIR"); d != "" {
		return d
	}
	switch runtime.GOOS {
	case "windows":
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		return filepath.Join(pd, "SCIAT", "Agent")
	case "darwin":
		return "/Library/Application Support/SCIAT"
	default:
		return "/etc/sciat-agent"
	}
}

// Path is the configuration file for this platform.
func Path() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(Dir(), "agent.json")
	}
	return filepath.Join(Dir(), "agent.conf")
}

// Load reads a configuration file in either format.
func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var c Config
	if strings.HasSuffix(strings.ToLower(path), ".json") {
		// PowerShell may write a UTF-8 byte order mark.
		if err := json.Unmarshal([]byte(strings.TrimPrefix(string(raw), "\ufeff")), &c); err != nil {
			return Config{}, fmt.Errorf("%s: %w", path, err)
		}
	} else {
		sc := bufio.NewScanner(strings.NewReader(string(raw)))
		for sc.Scan() {
			k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
			if !ok || strings.HasPrefix(k, "#") {
				continue
			}
			v = strings.TrimSpace(v)
			if len(v) >= 2 && (v[0] == '\'' || v[0] == '"') && v[len(v)-1] == v[0] {
				v = v[1 : len(v)-1]
			}
			switch k {
			case "PLATFORM_URL":
				c.PlatformURL = v
			case "AGENT_TOKEN":
				c.AgentToken = v
			}
		}
	}
	c.PlatformURL = strings.TrimRight(c.PlatformURL, "/")
	return c, c.Validate()
}

// Save writes the configuration readable by its owner only.
func Save(path string, c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	var data []byte
	if strings.HasSuffix(strings.ToLower(path), ".json") {
		data, _ = json.MarshalIndent(c, "", "  ")
	} else {
		if strings.ContainsAny(c.PlatformURL+c.AgentToken, "'\n") {
			return errors.New("configuration values contain quotes or newlines")
		}
		data = []byte(fmt.Sprintf("PLATFORM_URL='%s'\nAGENT_TOKEN='%s'\n", c.PlatformURL, c.AgentToken))
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
