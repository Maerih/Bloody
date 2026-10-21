//go:build !windows

package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sciat.africa/agent/internal/isolation"
)

// fakeHelper installs a bloody-isolate that records its arguments.
func fakeHelper(t *testing.T) (isolation.Helper, string) {
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	script := `#!/bin/sh
echo "$@" >> ` + log + `
case "$1" in
  isolate) echo "isolated ($2)"; echo "isolated" > ` + dir + `/state; echo "mode=$2" >> ` + dir + `/state ;;
  release) echo "released"; rm -f ` + dir + `/state ;;
  status) if [ -f ` + dir + `/state ]; then cat ` + dir + `/state; else echo not_isolated; fi ;;
esac
`
	os.WriteFile(filepath.Join(dir, "bloody-isolate"), []byte(script), 0o755)
	return isolation.Helper{Home: dir}, log
}

func TestRefusesAnythingButBuiltInCommands(t *testing.T) {
	h, log := fakeHelper(t)
	r := Runner{Isolation: h, Harden: func(string) (string, error) { t.Fatal("harden must not run"); return "", nil }}
	for _, args := range [][]string{{}, {"rm", "-rf", "/"}, {"isolate", "full;", "reboot"}, {"isolate", "$(id)"}, {"harden"}, {"harden", "a", "b"}, {"harden", "Bad-Check"}} {
		if res := r.Run(args); res.OK || !strings.HasPrefix(res.Output, "refused") {
			t.Fatalf("%v: %+v", args, res)
		}
	}
	if _, err := os.Stat(log); err == nil {
		t.Fatal("the helper ran for a refused command")
	}
}

func TestIsolateAndReleaseThroughTheHelper(t *testing.T) {
	h, log := fakeHelper(t)
	r := Runner{Isolation: h}
	res := r.Run([]string{"isolate", "lan", "allow=10.0.0.1", "block4=10.0.0.0/8"})
	if !res.OK || !strings.Contains(res.Output, "mode=lan") {
		t.Fatalf("isolate: %+v", res)
	}
	if st, mode := h.Status(); st != "isolated" || mode != "lan" {
		t.Fatalf("status %s %s", st, mode)
	}
	if res := r.Run([]string{"release"}); !res.OK {
		t.Fatalf("release: %+v", res)
	}
	calls, _ := os.ReadFile(log)
	if !strings.Contains(string(calls), "isolate lan allow=10.0.0.1 block4=10.0.0.0/8") {
		t.Fatalf("helper got %q", calls)
	}
}

func TestHardenAsksForAReport(t *testing.T) {
	r := Runner{Harden: func(c string) (string, error) { return "done " + c, nil }}
	if res := r.Run([]string{"harden", "linux_aslr"}); !res.OK || !res.Reinventory || res.Output != "done linux_aslr" {
		t.Fatalf("%+v", res)
	}
}
