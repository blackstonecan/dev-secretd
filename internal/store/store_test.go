package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	return s, dir
}

func runSecret(name, value string) Secret {
	return Secret{Project: "demo", Name: name, Tier: TierRun, Kind: KindEnv, Value: value}
}

func TestCreateGetList(t *testing.T) {
	s, _ := newStore(t)
	now := time.Now()
	if err := s.Create(runSecret("DB_PASSWORD", "pw1"), now); err != nil {
		t.Fatal(err)
	}
	proxy := Secret{Project: "demo", Name: "API_KEY", Tier: TierProxy, Value: "sk-1",
		Binding: &Binding{Host: "api.example.com", Header: "x-api-key"}}
	if err := s.Create(proxy, now); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get("demo", "DB_PASSWORD")
	if err != nil || got.Value != "pw1" {
		t.Fatalf("get: %v %+v", err, got)
	}
	list, err := s.List("demo")
	if err != nil || len(list) != 2 || list[0].Name != "API_KEY" {
		t.Fatalf("list: %v %+v", err, list)
	}
	if _, err := s.Get("demo", "NOPE"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestCreateNeverReplaces(t *testing.T) {
	s, _ := newStore(t)
	if err := s.Create(runSecret("TOKEN", "a"), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(runSecret("TOKEN", "b"), time.Now()); !errors.Is(err, ErrExists) {
		t.Fatalf("want ErrExists, got %v", err)
	}
	got, _ := s.Get("demo", "TOKEN")
	if got.Value != "a" {
		t.Fatalf("value changed to %q", got.Value)
	}
}

func TestSetDefault(t *testing.T) {
	s, _ := newStore(t)
	user := Secret{Project: UserProject, Name: "GITHUB_TOKEN", Tier: TierRun, Kind: KindEnv, Value: "gh"}
	if err := s.Create(user, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDefault(UserProject, "GITHUB_TOKEN", true, time.Now()); err != nil {
		t.Fatal(err)
	}
	// Rotating and rebinding keep the default.
	if err := s.Rotate(UserProject, "GITHUB_TOKEN", "gh2", time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Get(UserProject, "GITHUB_TOKEN"); !got.Default || got.Value != "gh2" {
		t.Fatalf("after rotate: %+v", got)
	}
	if err := s.SetDefault(UserProject, "GITHUB_TOKEN", false, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Get(UserProject, "GITHUB_TOKEN"); got.Default {
		t.Fatal("default not cleared")
	}
	if err := s.Create(runSecret("TOKEN", "a"), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDefault("demo", "TOKEN", true, time.Now()); err == nil {
		t.Fatal("a project secret became a default")
	}
	if err := s.SetDefault(UserProject, "MISSING", true, time.Now()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestFileIsEncrypted(t *testing.T) {
	s, dir := newStore(t)
	if err := s.Create(runSecret("TOKEN", "super-secret-value"), time.Now()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "store.enc"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("super-secret-value")) || bytes.Contains(raw, []byte("TOKEN")) {
		t.Fatal("store file contains plaintext")
	}
	other, _ := NewKey()
	s2, _ := Open(dir, other)
	if _, err := s2.List(""); err == nil {
		t.Fatal("a wrong key must not decrypt the store")
	}
}

func TestValidate(t *testing.T) {
	cases := map[string]Secret{
		"bad project":       {Project: "Demo", Name: "A", Tier: TierRun, Kind: KindEnv, Value: "v"},
		"bad name":          {Project: "demo", Name: "lower", Tier: TierRun, Kind: KindEnv, Value: "v"},
		"empty value":       {Project: "demo", Name: "A", Tier: TierRun, Kind: KindEnv},
		"run with binding":  {Project: "demo", Name: "A", Tier: TierRun, Kind: KindEnv, Value: "v", Binding: &Binding{Host: "h", Header: "x"}},
		"proxy no binding":  {Project: "demo", Name: "A", Tier: TierProxy, Value: "v"},
		"header and query":  {Project: "demo", Name: "A", Tier: TierProxy, Value: "v", Binding: &Binding{Host: "h.com", Header: "x", Query: "k"}},
		"bad host":          {Project: "demo", Name: "A", Tier: TierProxy, Value: "v", Binding: &Binding{Host: "h.com/evil", Header: "x"}},
		"format without {}": {Project: "demo", Name: "A", Tier: TierProxy, Value: "v", Binding: &Binding{Host: "h.com", Header: "x", Format: "Bearer"}},
		"unknown tier":      {Project: "demo", Name: "A", Tier: "plain", Value: "v"},
		"project default":   {Project: "demo", Name: "A", Tier: TierRun, Kind: KindEnv, Value: "v", Default: true},
	}
	for name, sec := range cases {
		if err := sec.Validate(); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}
