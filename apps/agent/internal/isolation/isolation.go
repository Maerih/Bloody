// Package isolation drives the bloody-isolate helper installed next to the agent (firewall rules
// that cut the computer off while keeping the platform reachable).
package isolation

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Helper runs the platform's isolation helper from the agent's directory.
type Helper struct{ Home string }

func (h Helper) command(ctx context.Context, args ...string) (*exec.Cmd, bool) {
	if runtime.GOOS == "windows" {
		script := filepath.Join(h.Home, "bloody-isolate.ps1")
		if _, err := os.Stat(script); err != nil {
			return nil, false
		}
		return exec.CommandContext(ctx, "powershell.exe", append([]string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script}, args...)...), true
	}
	bin := filepath.Join(h.Home, "bloody-isolate")
	if st, err := os.Stat(bin); err != nil || st.Mode()&0o111 == 0 {
		return nil, false
	}
	return exec.CommandContext(ctx, bin, args...), true
}

// Available is true when the helper is installed.
func (h Helper) Available() bool {
	_, ok := h.command(context.Background())
	return ok
}

// Status is "isolated" (with mode "lan" / "full"), "not_isolated" or "unknown".
func (h Helper) Status() (state, mode string) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd, ok := h.command(ctx, "status")
	if !ok {
		return "unknown", ""
	}
	out, _ := cmd.Output()
	lines := strings.Split(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n")
	if strings.TrimSpace(lines[0]) != "isolated" {
		return "not_isolated", ""
	}
	mode = "unknown"
	for _, l := range lines[1:] {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "mode="); ok {
			mode = v
		}
	}
	return "isolated", mode
}

// Run executes "isolate <mode> …" or "release" and returns the helper's output.
func (h Helper) Run(args []string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd, ok := h.command(ctx, args...)
	if !ok {
		return "isolation is not available on this endpoint", errUnavailable
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

type unavailable struct{}

func (unavailable) Error() string { return "isolation helper not installed" }

var errUnavailable error = unavailable{}
