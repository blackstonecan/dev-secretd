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

	"github.com/blackstonecan/dev-secretd/internal/state"
	"github.com/blackstonecan/dev-secretd/internal/store"
)

// wsUpstream is a TLS server that accepts a WebSocket-style upgrade, records
// the Authorization header, and then echoes each line it receives, with the
// secret value appended once, so the test can see whether the upgraded
// stream is masked.
func wsUpstream(t *testing.T, h2 bool) (*httptest.Server, *string) {
	t.Helper()
	var auth string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "not an upgrade", http.StatusBadRequest)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Upgrade", "websocket")
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Sec-WebSocket-Accept", "fake-accept")
		w.Header().Set("X-Echo-Auth", auth)
		w.WriteHeader(http.StatusSwitchingProtocols)
		conn, rw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		rw.Flush()
		for {
			line, err := rw.ReadString('\n')
			if err != nil {
				return
			}
			rw.WriteString("echo " + strings.TrimSpace(line) + " ws-token-123\n")
			rw.Flush()
		}
	}))
	srv.EnableHTTP2 = h2
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, &auth
}

func wsProxy(t *testing.T, upstream *httptest.Server) (*httptest.Server, string) {
	t.Helper()
	dir := t.TempDir()
	key, _ := store.NewKey()
	s, _ := store.Open(dir, key)
	must(t, s.Create(store.Secret{Project: "agent", Name: "AGENT_KEY", Tier: store.TierProxy, Value: "ws-token-123",
		Binding: &store.Binding{Host: strings.TrimPrefix(upstream.URL, "https://"), Header: "Authorization", Format: "Bearer {}"}}, time.Now()))
	st, _ := state.Load(dir)
	p := httptest.NewServer(&Proxy{Store: s, State: st, Audit: state.NewAudit(dir), Transport: upstream.Client().Transport})
	t.Cleanup(p.Close)
	return p, dir
}

// waitAudit waits until the proxy has written its audit line for the
// request, which happens after the upgraded connection closes.
func waitAudit(t *testing.T, dir string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		raw, _ := os.ReadFile(filepath.Join(dir, "audit.log"))
		if strings.Contains(string(raw), `"op":"proxy"`) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no audit line after the upgrade")
}

// A WebSocket upgrade through the proxy reaches the HTTPS upstream with the
// secret header added. The upgraded stream is copied as is, in both
// directions; it is not masked (the 101 response headers are).
func TestWebSocketUpgrade(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		upstream, auth := wsUpstream(t, h2)
		p, dir := wsProxy(t, upstream)

		conn, err := net.Dial("tcp", strings.TrimPrefix(p.URL, "http://"))
		must(t, err)
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		io.WriteString(conn, "GET /agent/AGENT_KEY/ws?room=1 HTTP/1.1\r\n"+
			"Host: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"+
			"Authorization: Bearer placeholder\r\n\r\n")
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, nil)
		must(t, err)
		if resp.StatusCode != http.StatusSwitchingProtocols {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("h2=%v: status %d: %s", h2, resp.StatusCode, body)
		}
		if *auth != "Bearer ws-token-123" {
			t.Fatalf("h2=%v: upstream got Authorization %q", h2, *auth)
		}
		if got := resp.Header.Get("X-Echo-Auth"); got != "Bearer ***" {
			t.Fatalf("h2=%v: 101 header not masked: %q", h2, got)
		}
		io.WriteString(conn, "ping\n")
		line, err := br.ReadString('\n')
		must(t, err)
		// Documented limit: after the 101 the bytes flow raw, so a value the
		// upstream sends on the socket is not masked.
		if line != "echo ping ws-token-123\n" {
			t.Fatalf("h2=%v: upgraded stream: %q", h2, line)
		}
		conn.Close()
		waitAudit(t, dir)
	}
}
