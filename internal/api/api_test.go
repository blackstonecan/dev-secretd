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
	return NewClient(sock), st
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
