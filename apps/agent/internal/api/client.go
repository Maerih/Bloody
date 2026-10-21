// Package api is the agent side of the SCIAT platform's endpoint API (/api/v1/agent/…).
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// HTTPError is a non-2xx answer from the platform.
type HTTPError struct {
	Status     int
	Body       string
	RetryAfter time.Duration
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("platform answered HTTP %d: %s", e.Status, strings.TrimSpace(e.Body))
}

// Retryable is true for "busy" (429) and server errors.
func (e *HTTPError) Retryable() bool { return e.Status == http.StatusTooManyRequests || e.Status >= 500 }

// Client talks to one platform with one agent token.
type Client struct {
	base  string
	token string
	http  *http.Client
}

// PinFunc returns the address to connect to instead of resolving the platform's name (used while
// the computer is isolated and DNS may be blocked), or "" to resolve normally.
type PinFunc func() string

// New creates a client. TLS certificates are always verified (against the platform's host name,
// also when connecting to a pinned address).
func New(baseURL, token string, pin PinFunc) *Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConns:        4,
		IdleConnTimeout:     90 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if pin != nil {
				if ip := pin(); ip != "" {
					_, port, err := net.SplitHostPort(addr)
					if err == nil {
						addr = net.JoinHostPort(ip, port)
					}
				}
			}
			return dialer.DialContext(ctx, network, addr)
		},
	}
	return &Client{base: strings.TrimRight(baseURL, "/"), token: token, http: &http.Client{Transport: tr, Timeout: 60 * time.Second}}
}

// Post sends JSON to /api/v1<path> and decodes the JSON answer into out (when not nil).
func (c *Client) Post(ctx context.Context, path string, in, out any) error {
	return do(ctx, c.http, http.MethodPost, c.base+"/api/v1"+path, c.token, in, out)
}

// Get downloads /api/v1<path>.
func (c *Client) Get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/api/v1"+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("authorization", "Bearer "+c.token)
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 300 {
		return nil, &HTTPError{Status: res.StatusCode, Body: string(body[:min(len(body), 300)]), RetryAfter: retryAfter(res)}
	}
	return body, nil
}

func do(ctx context.Context, hc *http.Client, method, u, token string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("user-agent", "SCIAT-Agent")
	if token != "" {
		req.Header.Set("authorization", "Bearer "+token)
	}
	res, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return err
	}
	if res.StatusCode >= 300 {
		return &HTTPError{Status: res.StatusCode, Body: string(raw[:min(len(raw), 300)]), RetryAfter: retryAfter(res)}
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func retryAfter(res *http.Response) time.Duration {
	if s, err := strconv.Atoi(strings.TrimSpace(res.Header.Get("retry-after"))); err == nil && s >= 0 && s <= 3600 {
		return time.Duration(s) * time.Second
	}
	return 0
}

// backoffUnit scales enrollment retries (tests shorten it).
var backoffUnit = time.Second

// EnrollRequest is the one-time registration with the account and organization keys.
type EnrollRequest struct {
	AccountKey      string   `json:"accountKey"`
	OrganizationKey string   `json:"organizationKey"`
	Hostname        string   `json:"hostname"`
	Platform        string   `json:"platform"`
	OS              string   `json:"os,omitempty"`
	Version         string   `json:"version"`
	IPs             []string `json:"ips,omitempty"`
	MachineID       string   `json:"machineId,omitempty"`
}

// EnrollResponse carries the agent's own token.
type EnrollResponse struct {
	AgentID        string `json:"agentId"`
	Token          string `json:"token"`
	OrganizationID string `json:"organizationId"`
	PollSeconds    int    `json:"pollSeconds"`
}

// Enroll registers the computer, retrying while the platform is busy (mass deployments): up to
// 8 attempts, honouring Retry-After plus jitter, like the script installers.
func Enroll(ctx context.Context, baseURL string, req EnrollRequest) (EnrollResponse, error) {
	if _, err := url.Parse(baseURL); err != nil {
		return EnrollResponse{}, err
	}
	hc := &http.Client{Timeout: 30 * time.Second}
	var res EnrollResponse
	var last error
	for attempt := 1; attempt <= 8; attempt++ {
		last = do(ctx, hc, http.MethodPost, strings.TrimRight(baseURL, "/")+"/api/v1/agent/enroll", "", req, &res)
		if last == nil {
			if !strings.HasPrefix(res.Token, "sat_") {
				return res, errors.New("the platform did not return an agent token")
			}
			return res, nil
		}
		var he *HTTPError
		wait := time.Duration(0)
		if errors.As(last, &he) {
			if !he.Retryable() {
				return res, last
			}
			wait = he.RetryAfter * backoffUnit / time.Second
		}
		if wait == 0 {
			wait = time.Duration(attempt*5) * backoffUnit
		}
		wait += time.Duration(rand.Int63n(int64(5 * backoffUnit)))
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		case <-time.After(wait):
		}
	}
	return res, fmt.Errorf("enrollment failed after 8 attempts: %w", last)
}

// HeartbeatRequest is a check-in: liveness and host facts.
type HeartbeatRequest struct {
	Hostname      string            `json:"hostname"`
	OS            string            `json:"os,omitempty"`
	Version       string            `json:"version"`
	IPs           []string          `json:"ips"`
	UptimeSeconds int64             `json:"uptimeSeconds"`
	Isolation     Isolation         `json:"isolation"`
	Engines       map[string]string `json:"engines"`
	PlatformIPs   []string          `json:"platformIps"`
	DNSServers    []string          `json:"dnsServers"`
}

// Isolation is the computer's own view of its isolation state.
type Isolation struct {
	State string `json:"state"`
	Mode  string `json:"mode,omitempty"`
}

// Command is an instruction queued for this computer (isolate / release / harden).
type Command struct {
	ID   string   `json:"id"`
	Args []string `json:"args"`
}

// HeartbeatResponse lists queued commands and how long to wait before the next check-in.
type HeartbeatResponse struct {
	PollSeconds    int        `json:"pollSeconds"`
	AppControlEtag string     `json:"appControlEtag"`
	ServerTime     string     `json:"serverTime"`
	Commands       []Command  `json:"commands"`
	Update         *UpdateOff `json:"update"`
}

// UpdateOff is a newer agent version the platform offers.
type UpdateOff struct {
	Version string `json:"version"`
	Files   []struct {
		Name   string `json:"name"`
		Target string `json:"target"`
		SHA256 string `json:"sha256"`
	} `json:"files"`
}

// CommandResult reports what a command did.
type CommandResult struct {
	Status string `json:"status"`
	Output string `json:"output"`
}

func splitHostPort(addr string) (string, string, error) { return net.SplitHostPort(addr) }
