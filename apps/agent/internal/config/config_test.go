package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadsBothScriptAgentFormats(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "agent.conf")
	os.WriteFile(conf, []byte("# SCIAT\nPLATFORM_URL='https://soc.example.com/'\nAGENT_TOKEN='sat_abc_def_ghi'\n"), 0o600)
	c, err := Load(conf)
	if err != nil || c.PlatformURL != "https://soc.example.com" || c.AgentToken != "sat_abc_def_ghi" {
		t.Fatalf("shell format: %+v %v", c, err)
	}
	js := filepath.Join(dir, "agent.json")
	os.WriteFile(js, []byte("\ufeff{\"platformUrl\":\"https://soc.example.com\",\"agentToken\":\"sat_x_y_z\"}"), 0o600)
	c, err = Load(js)
	if err != nil || c.AgentToken != "sat_x_y_z" {
		t.Fatalf("PowerShell format with BOM: %+v %v", c, err)
	}
}

func TestSaveRoundTripAndPermissions(t *testing.T) {
	for _, name := range []string{"agent.conf", "agent.json"} {
		p := filepath.Join(t.TempDir(), "sub", name)
		in := Config{PlatformURL: "https://soc.example.com", AgentToken: "sat_1_2_3"}
		if err := Save(p, in); err != nil {
			t.Fatal(err)
		}
		out, err := Load(p)
		if err != nil || out != in {
			t.Fatalf("%s: %+v %v", name, out, err)
		}
		if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
			t.Fatalf("%s: mode %v", name, st.Mode().Perm())
		}
	}
}

func TestRefusesBadValues(t *testing.T) {
	if err := Save(filepath.Join(t.TempDir(), "agent.conf"), Config{PlatformURL: "ftp://x", AgentToken: "sat_1"}); err == nil {
		t.Fatal("accepted a non-http URL")
	}
	if err := Save(filepath.Join(t.TempDir(), "agent.conf"), Config{PlatformURL: "https://x", AgentToken: "nope"}); err == nil {
		t.Fatal("accepted a malformed token")
	}
	if err := Save(filepath.Join(t.TempDir(), "agent.conf"), Config{PlatformURL: "https://x/'$(id)", AgentToken: "sat_1"}); err == nil {
		t.Fatal("accepted a quote that would break the shell format")
	}
}
