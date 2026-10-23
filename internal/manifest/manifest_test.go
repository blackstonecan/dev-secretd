package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), FileName)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFallback(t *testing.T) {
	m, err := Load(write(t, "project: demo\nsecrets:\n  NPM_TOKEN:\n    tier: run\n    fallback: user\n  DB_PASSWORD:\n    tier: run\n  GH:\n    tier: run\n    fallback: none\n"))
	if err != nil {
		t.Fatal(err)
	}
	if m.Secrets["NPM_TOKEN"].Fallback != "user" || m.Secrets["DB_PASSWORD"].Fallback != "" || m.Secrets["GH"].Fallback != "none" {
		t.Fatalf("fallback: %+v", m.Secrets)
	}
}

func TestPublicEntry(t *testing.T) {
	m, err := Load(write(t, "project: demo\nsecrets:\n  GITHUB_USERNAME:\n    tier: public\n  ORG:\n    tier: public\n    var: GITHUB_ORG\n"))
	if err != nil || m.Secrets["GITHUB_USERNAME"].Tier != "public" || m.Secrets["ORG"].Var != "GITHUB_ORG" {
		t.Fatalf("public entries: %+v %v", m, err)
	}
	if _, err := Load(write(t, "project: demo\nsecrets:\n  X:\n    tier: public\n    env:\n      A: b\n")); err == nil || !strings.Contains(err.Error(), "a public entry has var, not env") {
		t.Fatalf("public with env: %v", err)
	}
}

func TestFallbackErrors(t *testing.T) {
	for body, want := range map[string]string{
		"project: demo\nsecrets:\n  NPM_TOKEN:\n    tier: run\n    fallback: team\n": `fallback must be "user"`,
		"project: user\nsecrets:\n  NPM_TOKEN:\n    tier: run\n    fallback: user\n": "the user manifest has no fallback",
		"project: user\nsecrets:\n  NPM_TOKEN:\n    tier: run\n    fallback: none\n": "the user manifest has no fallback",
	} {
		if _, err := Load(write(t, body)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q, got %v", want, err)
		}
	}
}

func TestLoadUser(t *testing.T) {
	cfg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfg)
	p, err := UserPath()
	if err != nil || p != filepath.Join(cfg, "secretd", "user.yaml") {
		t.Fatalf("UserPath: %q %v", p, err)
	}
	if _, err := LoadUser(); !os.IsNotExist(err) {
		t.Fatalf("missing user manifest: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("project: demo\nsecrets: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadUser(); err == nil || !strings.Contains(err.Error(), `project must be "user"`) {
		t.Fatalf("want project check, got %v", err)
	}
	if err := os.WriteFile(p, []byte("project: user\nsecrets:\n  NPM_TOKEN:\n    tier: run\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if m, err := LoadUser(); err != nil || m.Secrets["NPM_TOKEN"].Tier != "run" {
		t.Fatalf("LoadUser: %+v %v", m, err)
	}
}
