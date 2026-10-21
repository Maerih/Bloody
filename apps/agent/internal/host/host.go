// Package host collects the facts sent with every check-in.
package host

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Hostname as the operating system reports it.
func Hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "unknown"
	}
	return h
}

// IPs are the computer's own addresses (no loopback / link-local), at most 16.
func IPs() []string {
	var out []string
	ifs, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.IsLoopback() || ipn.IP.IsLinkLocalUnicast() || ipn.IP.IsMulticast() {
				continue
			}
			out = append(out, ipn.IP.String())
			if len(out) == 16 {
				return out
			}
		}
	}
	return out
}

// PlatformIPs resolves the platform's host name and caches the answer in stateDir, so the agent
// keeps reaching the platform when the computer is isolated and DNS is blocked.
func PlatformIPs(host, stateDir string) []string {
	cache := filepath.Join(stateDir, "platform-ips")
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return []string{ip.String()}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err == nil && len(addrs) > 0 {
		seen := map[string]bool{}
		var out []string
		for _, a := range addrs {
			s := a.IP.String()
			if !seen[s] && len(out) < 8 {
				seen[s] = true
				out = append(out, s)
			}
		}
		sort.Strings(out)
		_ = os.WriteFile(cache, []byte(strings.Join(out, "\n")+"\n"), 0o600)
		return out
	}
	return CachedPlatformIPs(stateDir)
}

// CachedPlatformIPs are the addresses resolved last time.
func CachedPlatformIPs(stateDir string) []string {
	raw, err := os.ReadFile(filepath.Join(stateDir, "platform-ips"))
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(string(raw), "\n") {
		if ip := net.ParseIP(strings.TrimSpace(l)); ip != nil {
			out = append(out, ip.String())
		}
	}
	return out
}

// onlyIPs keeps unique, non-loopback addresses (at most 8).
func onlyIPs(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		ip := net.ParseIP(strings.TrimSpace(s))
		if ip == nil || ip.IsLoopback() || seen[ip.String()] {
			continue
		}
		seen[ip.String()] = true
		out = append(out, ip.String())
		if len(out) == 8 {
			break
		}
	}
	return out
}
