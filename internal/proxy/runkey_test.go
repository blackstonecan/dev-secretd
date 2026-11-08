package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blackstonecan/dev-secretd/internal/runkey"
	"github.com/blackstonecan/dev-secretd/internal/state"
	"github.com/blackstonecan/dev-secretd/internal/store"
)

type keyedFixture struct {
	f    *fixture
	keys *runkey.Registry
	dir  string
	st   *state.State
	url  string
}

// setupKeyed has a keyed secret MAIL, a plain secret PLAIN and a second keyed
// secret OTHER, all bound to the same upstream.
func setupKeyed(t *testing.T) *keyedFixture {
	t.Helper()
	f := &fixture{}
	f.upstream = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.lastReq = r.Clone(r.Context())
		io.WriteString(w, "ok")
	}))
	t.Cleanup(f.upstream.Close)
	dir := t.TempDir()
	key, _ := store.NewKey()
	s, _ := store.Open(dir, key)
	host := strings.TrimPrefix(f.upstream.URL, "https://")
	for _, c := range []struct {
		name   string
		runKey bool
	}{{"MAIL", true}, {"OTHER", true}, {"PLAIN", false}} {
		must(t, s.Create(store.Secret{Project: "demo", Name: c.name, Tier: store.TierProxy, Value: "sk-real-" + c.name,
			Binding: &store.Binding{Host: host, Header: "x-api-key", RunKey: c.runKey}}, time.Now()))
	}
	st, _ := state.Load(dir)
	keys := runkey.New()
	p := httptest.NewServer(&Proxy{Store: s, State: st, Audit: state.NewAudit(dir), Transport: f.upstream.Client().Transport, Keys: keys})
	t.Cleanup(p.Close)
	return &keyedFixture{f: f, keys: keys, dir: dir, st: st, url: p.URL}
}

func (k *keyedFixture) audit(t *testing.T) string {
	t.Helper()
	raw, _ := os.ReadFile(filepath.Join(k.dir, "audit.log"))
	return string(raw)
}

func TestRunKeyRequired(t *testing.T) {
	k := setupKeyed(t)
	key, _, _ := k.keys.Issue([]string{"demo/MAIL"})

	resp, body := get(t, k.url+"/demo/MAIL/v1/x", nil)
	if resp.StatusCode != 401 || !strings.Contains(body, "needs a per-run key") {
		t.Fatalf("no key: %d %s", resp.StatusCode, body)
	}
	if k.f.lastReq != nil {
		t.Fatal("request without a key reached the upstream")
	}
	if a := k.audit(t); !strings.Contains(a, "needs a per-run key") {
		t.Fatalf("audit has no refusal: %s", a)
	}

	resp, _ = get(t, k.url+"/demo/MAIL/rk-"+strings.Repeat("0", 64)+"/v1/x", nil)
	if resp.StatusCode != 403 {
		t.Fatalf("wrong key: %d", resp.StatusCode)
	}

	// A key for another secret does not work.
	resp, _ = get(t, k.url+"/demo/OTHER/rk-"+key+"/v1/x", nil)
	if resp.StatusCode != 403 {
		t.Fatalf("key for another secret: %d", resp.StatusCode)
	}

	// Valid key in the path: the segment is removed before the upstream.
	resp, body = get(t, k.url+"/demo/MAIL/rk-"+key+"/v1/x?a=1", map[string]string{RunKeyHeader: "junk"})
	if resp.StatusCode != 200 || body != "ok" {
		t.Fatalf("valid key: %d %s", resp.StatusCode, body)
	}
	if k.f.lastReq.URL.Path != "/v1/x" || k.f.lastReq.URL.RawQuery != "a=1" {
		t.Fatalf("upstream path %q query %q", k.f.lastReq.URL.Path, k.f.lastReq.URL.RawQuery)
	}
	if k.f.lastReq.Header.Get(RunKeyHeader) != "" || k.f.lastReq.Header.Get("x-api-key") != "sk-real-MAIL" {
		t.Fatalf("upstream headers: %v", k.f.lastReq.Header)
	}

	// Valid key in the header, with and without the prefix.
	for _, v := range []string{key, "rk-" + key} {
		resp, _ = get(t, k.url+"/demo/MAIL/v1/y", map[string]string{RunKeyHeader: v})
		if resp.StatusCode != 200 || k.f.lastReq.URL.Path != "/v1/y" || k.f.lastReq.Header.Get(RunKeyHeader) != "" {
			t.Fatalf("header key: %d %q %v", resp.StatusCode, k.f.lastReq.URL.Path, k.f.lastReq.Header)
		}
	}

	// A bare base URL (no path) works too.
	resp, _ = get(t, k.url+"/demo/MAIL/rk-"+key, nil)
	if resp.StatusCode != 200 || k.f.lastReq.URL.Path != "/" {
		t.Fatalf("bare url: %d %q", resp.StatusCode, k.f.lastReq.URL.Path)
	}

	if strings.Contains(k.audit(t), key) {
		t.Fatal("audit log has the run key")
	}
}

func TestRunKeyRevokedAndLocked(t *testing.T) {
	k := setupKeyed(t)
	key, run, _ := k.keys.Issue([]string{"demo/MAIL"})
	if resp, _ := get(t, k.url+"/demo/MAIL/rk-"+key+"/x", nil); resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	must(t, k.st.SetLocked("demo", true, time.Now()))
	if resp, _ := get(t, k.url+"/demo/MAIL/rk-"+key+"/x", nil); resp.StatusCode != 403 {
		t.Fatalf("locked: %d", resp.StatusCode)
	}
	must(t, k.st.SetLocked("demo", false, time.Now()))
	k.keys.Revoke(run)
	resp, body := get(t, k.url+"/demo/MAIL/rk-"+key+"/x", nil)
	if resp.StatusCode != 403 || strings.Contains(body, key) {
		t.Fatalf("revoked: %d %s", resp.StatusCode, body)
	}
	if strings.Contains(k.audit(t), key) {
		t.Fatal("audit log has the run key")
	}
}

// A secret without run_key works without a key and keeps an "rk-" segment as path.
func TestPlainSecretIgnoresRunKey(t *testing.T) {
	k := setupKeyed(t)
	resp, _ := get(t, k.url+"/demo/PLAIN/v1/x", map[string]string{RunKeyHeader: "abc"})
	if resp.StatusCode != 200 || k.f.lastReq.URL.Path != "/v1/x" || k.f.lastReq.Header.Get(RunKeyHeader) != "" {
		t.Fatalf("plain: %d %q %v", resp.StatusCode, k.f.lastReq.URL.Path, k.f.lastReq.Header)
	}
	resp, _ = get(t, k.url+"/demo/PLAIN/rk-abc/v1/x", nil)
	if resp.StatusCode != 200 || k.f.lastReq.URL.Path != "/rk-abc/v1/x" {
		t.Fatalf("plain with segment: %d %q", resp.StatusCode, k.f.lastReq.URL.Path)
	}
}

func TestRunKeyWebSocket(t *testing.T) {
	upstream, _ := wsUpstream(t, false)
	dir := t.TempDir()
	key, _ := store.NewKey()
	s, _ := store.Open(dir, key)
	must(t, s.Create(store.Secret{Project: "agent", Name: "AGENT_KEY", Tier: store.TierProxy, Value: "ws-token-123",
		Binding: &store.Binding{Host: strings.TrimPrefix(upstream.URL, "https://"), Header: "Authorization", Format: "Bearer {}", RunKey: true}}, time.Now()))
	st, _ := state.Load(dir)
	keys := runkey.New()
	p := httptest.NewServer(&Proxy{Store: s, State: st, Audit: state.NewAudit(dir), Transport: upstream.Client().Transport, Keys: keys})
	t.Cleanup(p.Close)
	rk, _, _ := keys.Issue([]string{"agent/AGENT_KEY"})

	dial := func(path string) *http.Response {
		conn, err := net.Dial("tcp", strings.TrimPrefix(p.URL, "http://"))
		must(t, err)
		t.Cleanup(func() { conn.Close() })
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		io.WriteString(conn, "GET "+path+" HTTP/1.1\r\n"+
			"Host: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		must(t, err)
		return resp
	}
	if resp := dial("/agent/AGENT_KEY/ws"); resp.StatusCode != 401 {
		t.Fatalf("no key: %d", resp.StatusCode)
	}
	if resp := dial("/agent/AGENT_KEY/rk-" + rk + "/ws"); resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("with key: %d", resp.StatusCode)
	}
}
