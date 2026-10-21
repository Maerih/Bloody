package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestEnrollRetriesWhileBusyThenSucceeds(t *testing.T) {
	backoffUnit = time.Millisecond
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/enroll" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		var req EnrollRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.AccountKey != "sak_test" || req.Platform == "" {
			t.Errorf("bad body %+v", req)
		}
		if calls.Add(1) < 3 {
			w.Header().Set("retry-after", "2")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		json.NewEncoder(w).Encode(EnrollResponse{AgentID: "a1", Token: "sat_t_a_b", PollSeconds: 60})
	}))
	defer srv.Close()
	res, err := Enroll(context.Background(), srv.URL, EnrollRequest{AccountKey: "sak_test", OrganizationKey: "acme", Hostname: "h", Platform: "linux", Version: "2"})
	if err != nil || res.Token != "sat_t_a_b" || calls.Load() != 3 {
		t.Fatalf("res=%+v err=%v calls=%d", res, err, calls.Load())
	}
}

func TestEnrollStopsOnRefusal(t *testing.T) {
	backoffUnit = time.Millisecond
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":{"code":"invalid_account_key"}}`))
	}))
	defer srv.Close()
	_, err := Enroll(context.Background(), srv.URL, EnrollRequest{})
	if he, ok := err.(*HTTPError); !ok || he.Status != 401 || calls.Load() != 1 {
		t.Fatalf("err=%v calls=%d", err, calls.Load())
	}
}

func TestPinnedAddressIsUsedForTheConnection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("authorization") != "Bearer sat_tok" {
			t.Errorf("missing token")
		}
		w.Write([]byte(`{"pollSeconds":60,"commands":[]}`))
	}))
	defer srv.Close()
	_, port, _ := splitHostPort(srv.Listener.Addr().String())
	// A name that does not resolve: only the pinned address can reach the server.
	c := New("http://platform.invalid:"+port, "sat_tok", func() string { return "127.0.0.1" })
	var res HeartbeatResponse
	if err := c.Post(context.Background(), "/agent/heartbeat", map[string]string{}, &res); err != nil || res.PollSeconds != 60 {
		t.Fatalf("pinned request failed: %v", err)
	}
	unpinned := New("http://platform.invalid:"+port, "sat_tok", nil)
	if err := unpinned.Post(context.Background(), "/agent/heartbeat", map[string]string{}, nil); err == nil {
		t.Fatal("expected the unresolvable name to fail without a pin")
	}
}
