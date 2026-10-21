// Package service installs the agent as an operating-system service (systemd on Linux, the
// Service Control Manager on Windows) and fetches its helper files from the platform.
package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// HelperFile is a file the platform serves to endpoints (/api/v1/agent/files/<name>).
type HelperFile struct {
	Served string
	Local  string
	Mode   os.FileMode
}

// FetchHelpers downloads the isolation helper and the inventory collectors into home. Each file
// is written next to its final name first and only then moved into place.
func FetchHelpers(ctx context.Context, platformURL, home string, files []HelperFile) error {
	hc := &http.Client{Timeout: 2 * time.Minute}
	for _, f := range files {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(platformURL, "/")+"/api/v1/agent/files/"+f.Served, nil)
		if err != nil {
			return err
		}
		res, err := hc.Do(req)
		if err != nil {
			return fmt.Errorf("download %s: %w", f.Served, err)
		}
		body, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
		res.Body.Close()
		if err != nil {
			return err
		}
		if res.StatusCode != http.StatusOK || len(body) == 0 {
			return fmt.Errorf("download %s: HTTP %d", f.Served, res.StatusCode)
		}
		dest := filepath.Join(home, f.Local)
		if err := os.WriteFile(dest+".new", body, f.Mode); err != nil {
			return err
		}
		if err := os.Rename(dest+".new", dest); err != nil {
			return err
		}
		sum := sha256.Sum256(body)
		fmt.Printf("  %s (sha256 %s…)\n", f.Local, hex.EncodeToString(sum[:])[:16])
	}
	return nil
}

// CopySelf installs the running executable at dest (replacing an older one).
func CopySelf(dest string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if abs, _ := filepath.Abs(self); abs == dest {
		return nil
	}
	in, err := os.Open(self)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	tmp := dest + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dest)
}
