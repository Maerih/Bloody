// Package commands runs what the platform asks a computer to do. Only built-in actions run
// (isolate, release, a fixed set of hardening fixes); the platform never sends script text.
package commands

import (
	"regexp"
	"strings"

	"sciat.africa/agent/internal/isolation"
)

var (
	idRE    = regexp.MustCompile(`^[0-9a-f-]{36}$`)
	wordRE  = regexp.MustCompile(`^[A-Za-z0-9.,:=/_-]+$`)
	checkRE = regexp.MustCompile(`^[a-z0-9_]{1,40}$`)
)

// Result of one command.
type Result struct {
	OK     bool
	Output string
	// Reinventory is set when the computer's state changed and should be reported straight away.
	Reinventory bool
}

// Runner executes commands on this computer.
type Runner struct {
	Isolation isolation.Helper
	// Harden applies one built-in hardening fix (per platform).
	Harden func(check string) (string, error)
}

// ValidID reports whether a command id looks like one the platform issues.
func ValidID(id string) bool { return idRE.MatchString(id) }

// Run validates and executes one command.
func (r Runner) Run(args []string) Result {
	if len(args) == 0 || (args[0] != "isolate" && args[0] != "release" && args[0] != "harden") {
		return Result{Output: "refused: unexpected command"}
	}
	for _, a := range args {
		if !wordRE.MatchString(a) {
			return Result{Output: "refused: unexpected command"}
		}
	}
	if args[0] == "harden" {
		if len(args) != 2 || !checkRE.MatchString(args[1]) {
			return Result{Output: "refused: unexpected command"}
		}
		if r.Harden == nil {
			return Result{Output: "no built-in fix for " + args[1]}
		}
		out, err := r.Harden(args[1])
		if err != nil {
			return Result{Output: strings.TrimSpace(out + "\n" + err.Error())}
		}
		return Result{OK: true, Output: out, Reinventory: true}
	}
	out, err := r.Isolation.Run(args)
	if err != nil {
		return Result{Output: strings.TrimSpace(out + "\n" + err.Error())}
	}
	state, mode := r.Isolation.Status()
	return Result{OK: true, Output: strings.TrimSpace(out) + "\n" + state + map[bool]string{true: "\nmode=" + mode, false: ""}[mode != ""]}
}
