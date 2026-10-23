package api

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blackstonecan/secretd/internal/state"
	"github.com/blackstonecan/secretd/internal/store"
)

// startServer serves the API on a temporary socket. allowUID lets a test
// refuse the current user.
func startServer(t *testing.T, allowUID int) (*Client, *state.State) {
	t.Helper()
	c, st, _ := startServerDir(t, allowUID)
	return c, st
}

// startServerDir also returns the state directory, which holds audit.log.
func startServerDir(t *testing.T, allowUID int) (*Client, *state.State, string) {
	t.Helper()
	dir := t.TempDir()
	key, _ := store.NewKey()
	s, _ := store.Open(dir, key)
	st, _ := state.Load(dir)
	srv := &Server{Store: s, State: st, Audit: state.NewAudit(dir), AllowUID: allowUID, ProxyAddr: "127.0.0.1:7777"}

	sock := filepath.Join(dir, "api.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: srv.Handler(), ConnContext: ConnContext}
	go hs.Serve(ln)
	t.Cleanup(func() { hs.Close() })
	return NewClient(sock), st, dir
}

func TestSetListResolve(t *testing.T) {
	c, _ := startServer(t, os.Getuid())
	must(t, c.Set(SetRequest{Project: "demo", Name: "DB_PASSWORD", Tier: store.TierRun, Value: "pw"}))
	must(t, c.Set(SetRequest{Project: "demo", Name: "API_KEY", Tier: store.TierProxy, Value: "sk",
		Binding: &store.Binding{Host: "api.example.com", Header: "x-api-key"}}))

	list, err := c.List("demo")
	must(t, err)
	if len(list) != 2 || list[1].Name != "DB_PASSWORD" || list[1].Kind != store.KindEnv {
		t.Fatalf("list: %+v", list)
	}

	res, err := c.Resolve(ResolveRequest{Project: "demo", Items: []ResolveItem{
		{Name: "API_KEY", Tier: store.TierProxy}, {Name: "DB_PASSWORD", Tier: store.TierRun},
	}})
	must(t, err)
	if res[0].Value != "" || res[0].BaseURL != "http://127.0.0.1:7777/demo/API_KEY" {
		t.Fatalf("proxy item leaked or wrong: %+v", res[0])
	}
	if res[1].Value != "pw" {
		t.Fatalf("run item: %+v", res[1])
	}
}

func TestSetIsCreateOnly(t *testing.T) {
	c, _ := startServer(t, os.Getuid())
	must(t, c.Set(SetRequest{Project: "demo", Name: "TOKEN", Tier: store.TierRun, Value: "a"}))
	if err := c.Set(SetRequest{Project: "demo", Name: "TOKEN", Tier: store.TierRun, Value: "b"}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("want already exists, got %v", err)
	}
}

func TestManifestCannotChangeTier(t *testing.T) {
	c, _ := startServer(t, os.Getuid())
	must(t, c.Set(SetRequest{Project: "demo", Name: "API_KEY", Tier: store.TierProxy, Value: "sk",
		Binding: &store.Binding{Host: "api.example.com", Header: "x-api-key"}}))
	_, err := c.Resolve(ResolveRequest{Project: "demo", Items: []ResolveItem{{Name: "API_KEY", Tier: store.TierRun}}})
	if err == nil || !strings.Contains(err.Error(), "the store says proxy") {
		t.Fatalf("want tier conflict, got %v", err)
	}
}

func TestLockBlocksResolve(t *testing.T) {
	c, _ := startServer(t, os.Getuid())
	must(t, c.Set(SetRequest{Project: "demo", Name: "TOKEN", Tier: store.TierRun, Value: "a"}))
	must(t, c.Lock("demo", true))
	if _, err := c.Resolve(ResolveRequest{Project: "demo", Items: []ResolveItem{{Name: "TOKEN", Tier: store.TierRun}}}); err == nil {
		t.Fatal("locked project resolved")
	}
	st, err := c.Status()
	must(t, err)
	if len(st.Locked) != 1 || st.Locked[0] != "demo" {
		t.Fatalf("status: %+v", st)
	}
	must(t, c.Lock("demo", false))
	if _, err := c.Resolve(ResolveRequest{Project: "demo", Items: []ResolveItem{{Name: "TOKEN", Tier: store.TierRun}}}); err != nil {
		t.Fatal(err)
	}
}

// userSecrets stores user-scope secrets: a proxy GITHUB_TOKEN and a run NPM_TOKEN.
func userSecrets(t *testing.T, c *Client) {
	t.Helper()
	must(t, c.Set(SetRequest{Project: store.UserProject, Name: "GITHUB_TOKEN", Tier: store.TierProxy, Value: "gh-user",
		Binding: &store.Binding{Host: "api.github.com", Header: "Authorization", Format: "Bearer {}"}}))
	must(t, c.Set(SetRequest{Project: store.UserProject, Name: "NPM_TOKEN", Tier: store.TierRun, Value: "npm-user"}))
}

func TestFallbackToUser(t *testing.T) {
	c, _, dir := startServerDir(t, os.Getuid())
	userSecrets(t, c)
	res, err := c.Resolve(ResolveRequest{Project: "demo", Items: []ResolveItem{
		{Name: "GITHUB_TOKEN", Tier: store.TierProxy, Fallback: "user"},
		{Name: "NPM_TOKEN", Tier: store.TierRun, Fallback: "user"},
	}})
	must(t, err)
	if res[0].Project != "user" || res[0].BaseURL != "http://127.0.0.1:7777/user/GITHUB_TOKEN" || res[0].Value != "" {
		t.Fatalf("proxy fallback: %+v", res[0])
	}
	if res[1].Project != "user" || res[1].Value != "npm-user" {
		t.Fatalf("run fallback: %+v", res[1])
	}
	raw, err := os.ReadFile(filepath.Join(dir, "audit.log"))
	must(t, err)
	if !strings.Contains(string(raw), `"project":"demo","name":"GITHUB_TOKEN"`) || !strings.Contains(string(raw), `"detail":"proxy from user"`) {
		t.Fatalf("audit does not show the fallback:\n%s", raw)
	}
	if strings.Contains(string(raw), "npm-user") || strings.Contains(string(raw), "gh-user") {
		t.Fatal("audit log has a value")
	}
}

func TestProjectSecretWinsOverUser(t *testing.T) {
	c, _ := startServer(t, os.Getuid())
	userSecrets(t, c)
	must(t, c.Set(SetRequest{Project: "demo", Name: "NPM_TOKEN", Tier: store.TierRun, Value: "npm-demo"}))
	res, err := c.Resolve(ResolveRequest{Project: "demo", Items: []ResolveItem{{Name: "NPM_TOKEN", Tier: store.TierRun, Fallback: "user"}}})
	must(t, err)
	if res[0].Project != "demo" || res[0].Value != "npm-demo" {
		t.Fatalf("project secret did not win: %+v", res[0])
	}
	// The user value is unchanged.
	res, err = c.Resolve(ResolveRequest{Project: "other", Items: []ResolveItem{{Name: "NPM_TOKEN", Tier: store.TierRun, Fallback: "user"}}})
	must(t, err)
	if res[0].Value != "npm-user" {
		t.Fatalf("user value changed: %+v", res[0])
	}
}

func TestNoFallbackWithoutOptIn(t *testing.T) {
	c, _ := startServer(t, os.Getuid())
	userSecrets(t, c)
	_, err := c.Resolve(ResolveRequest{Project: "demo", Items: []ResolveItem{{Name: "NPM_TOKEN", Tier: store.TierRun}}})
	if err == nil || !strings.Contains(err.Error(), "no secret demo/NPM_TOKEN") {
		t.Fatalf("want not found, got %v", err)
	}
}

func TestFallbackErrors(t *testing.T) {
	c, _ := startServer(t, os.Getuid())
	userSecrets(t, c)
	// A project secret with the wrong tier is an error, never a reason to fall back.
	must(t, c.Set(SetRequest{Project: "demo", Name: "GITHUB_TOKEN", Tier: store.TierRun, Value: "gh-demo"}))
	_, err := c.Resolve(ResolveRequest{Project: "demo", Items: []ResolveItem{{Name: "GITHUB_TOKEN", Tier: store.TierProxy, Fallback: "user"}}})
	if err == nil || !strings.Contains(err.Error(), "demo/GITHUB_TOKEN: the manifest says tier proxy, the store says run") {
		t.Fatalf("want project tier conflict, got %v", err)
	}
	// The user secret's tier must match too.
	_, err = c.Resolve(ResolveRequest{Project: "other", Items: []ResolveItem{{Name: "GITHUB_TOKEN", Tier: store.TierRun, Fallback: "user"}}})
	if err == nil || !strings.Contains(err.Error(), "user/GITHUB_TOKEN: the manifest says tier run, the store says proxy") {
		t.Fatalf("want user tier conflict, got %v", err)
	}
	_, err = c.Resolve(ResolveRequest{Project: "other", Items: []ResolveItem{{Name: "MISSING", Tier: store.TierRun, Fallback: "user"}}})
	if err == nil || !strings.Contains(err.Error(), "no secret other/MISSING or user/MISSING") {
		t.Fatalf("want not found in both, got %v", err)
	}
	_, err = c.Resolve(ResolveRequest{Project: "other", Items: []ResolveItem{{Name: "NPM_TOKEN", Tier: store.TierRun, Fallback: "team"}}})
	if err == nil || !strings.Contains(err.Error(), "invalid fallback") {
		t.Fatalf("want invalid fallback, got %v", err)
	}
	_, err = c.Resolve(ResolveRequest{Project: "user", Items: []ResolveItem{{Name: "NPM_TOKEN", Tier: store.TierRun, Fallback: "user"}}})
	if err == nil || !strings.Contains(err.Error(), "invalid fallback") {
		t.Fatalf("want invalid fallback for the user project, got %v", err)
	}
}

func TestLocksWithFallback(t *testing.T) {
	c, _ := startServer(t, os.Getuid())
	userSecrets(t, c)
	must(t, c.Set(SetRequest{Project: "demo", Name: "DB_PASSWORD", Tier: store.TierRun, Value: "pw"}))
	npm := ResolveItem{Name: "NPM_TOKEN", Tier: store.TierRun, Fallback: "user"}
	own := ResolveItem{Name: "DB_PASSWORD", Tier: store.TierRun}

	must(t, c.Lock("demo", true))
	if _, err := c.Resolve(ResolveRequest{Project: "demo", Items: []ResolveItem{npm}}); err == nil {
		t.Fatal("a locked project got a user secret")
	}
	must(t, c.Lock("demo", false))

	must(t, c.Lock("user", true))
	if _, err := c.Resolve(ResolveRequest{Project: "demo", Items: []ResolveItem{npm}}); err == nil || !strings.Contains(err.Error(), "project user is locked") {
		t.Fatalf("locked user scope: %v", err)
	}
	if _, err := c.Resolve(ResolveRequest{Project: "demo", Items: []ResolveItem{own}}); err != nil {
		t.Fatalf("own secrets must work while user is locked: %v", err)
	}
	// A project's own secret wins without touching the locked user scope.
	must(t, c.Set(SetRequest{Project: "demo", Name: "NPM_TOKEN", Tier: store.TierRun, Value: "npm-demo"}))
	if _, err := c.Resolve(ResolveRequest{Project: "demo", Items: []ResolveItem{npm}}); err != nil {
		t.Fatalf("own secret with fallback while user is locked: %v", err)
	}
}

func TestOtherUserIsRefused(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root is always allowed")
	}
	c, _ := startServer(t, os.Getuid()+1)
	if _, err := c.List(""); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("want refusal, got %v", err)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
