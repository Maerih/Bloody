//go:build !windows

package agent

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"sciat.africa/agent/internal/api"
	"sciat.africa/agent/internal/config"
)

const cmdID = "11111111-2222-4333-8444-555555555555"

func TestOneCycleChecksInRunsCommandsAndSendsInventory(t *testing.T) {
	var mu sync.Mutex
	got := map[string][]byte{}
	served := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("authorization") != "Bearer sat_tok_a_b" {
			w.WriteHeader(401)
			return
		}
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		got[r.URL.Path] = body
		mu.Unlock()
		switch r.URL.Path {
		case "/api/v1/agent/heartbeat":
			res := api.HeartbeatResponse{PollSeconds: 60}
			if !served {
				res.Commands = []api.Command{{ID: cmdID, Args: []string{"isolate", "full", "allow=192.0.2.10"}}, {ID: "not-an-id", Args: []string{"release"}}}
				served = true
			}
			json.NewEncoder(w).Encode(res)
		default:
			w.Write([]byte(`{"ok":true}`))
		}
	}))
	defer srv.Close()

	home := t.TempDir()
	state := t.TempDir()
	os.WriteFile(filepath.Join(home, "bloody-isolate"), []byte("#!/bin/sh\ncase \"$1\" in status) if [ -f "+home+"/iso ]; then printf 'isolated\\nmode=full\\n'; else echo not_isolated; fi;; isolate) touch "+home+"/iso; echo ok;; esac\n"), 0o755)
	os.WriteFile(filepath.Join(home, "sciat-agent"), []byte("#!/bin/bash\n[ \"$1\" = inventory ] && echo '{\"software\":[{\"name\":\"bash\"}]}'\n"), 0o755)

	a := New(config.Config{PlatformURL: srv.URL, AgentToken: "sat_tok_a_b"}, home, state, "2.0.0", log.New(io.Discard, "", 0))
	delay, err := a.Once(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if delay.Seconds() != 5 {
		t.Fatalf("after running a command the next check-in comes quickly, got %v", delay)
	}
	var hb api.HeartbeatRequest
	json.Unmarshal(got["/api/v1/agent/heartbeat"], &hb)
	if hb.Version != "2.0.0" || hb.Hostname == "" || hb.Isolation.State != "not_isolated" || hb.IPs == nil || hb.PlatformIPs == nil {
		t.Fatalf("heartbeat %+v", hb)
	}
	var result api.CommandResult
	json.Unmarshal(got["/api/v1/agent/commands/"+cmdID+"/result"], &result)
	if result.Status != "succeeded" || !strings.Contains(result.Output, "mode=full") {
		t.Fatalf("result %+v", result)
	}
	if _, ok := got["/api/v1/agent/commands/not-an-id/result"]; ok {
		t.Fatal("a command with a malformed id was run")
	}
	if !strings.Contains(string(got["/api/v1/agent/inventory"]), `"software"`) {
		t.Fatalf("inventory %s", got["/api/v1/agent/inventory"])
	}
	// Next cycle: isolated now, no inventory again before 30 minutes.
	delete(got, "/api/v1/agent/inventory")
	if _, err := a.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(got["/api/v1/agent/heartbeat"], &hb)
	if hb.Isolation.State != "isolated" || hb.Isolation.Mode != "full" {
		t.Fatalf("isolation %+v", hb.Isolation)
	}
	if _, ok := got["/api/v1/agent/inventory"]; ok {
		t.Fatal("inventory sent again within 30 minutes")
	}
	if _, err := os.Stat(filepath.Join(state, "last-checkin")); err != nil {
		t.Fatal("last-checkin not recorded")
	}
}
