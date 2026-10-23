package proxy

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blackstonecan/dev-secretd/internal/state"
	"github.com/blackstonecan/dev-secretd/internal/store"
)

type fixture struct {
	proxy    *httptest.Server
	st       *state.State
	lastReq  *http.Request
	upstream *httptest.Server
}

func setup(t *testing.T, binding store.Binding, upstreamBody string) *fixture {
	t.Helper()
	f := &fixture{}
	f.upstream = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.lastReq = r.Clone(r.Context())
		w.Header().Set("X-Echo", r.Header.Get("x-api-key"))
		io.WriteString(w, upstreamBody)
	}))
	t.Cleanup(f.upstream.Close)

	dir := t.TempDir()
	key, _ := store.NewKey()
	s, _ := store.Open(dir, key)
	binding.Host = strings.TrimPrefix(f.upstream.URL, "https://")
	must(t, s.Create(store.Secret{Project: "demo", Name: "API_KEY", Tier: store.TierProxy, Value: "sk-real-123", Binding: &binding}, time.Now()))
	must(t, s.Create(store.Secret{Project: "demo", Name: "DB_PASSWORD", Tier: store.TierRun, Kind: store.KindEnv, Value: "pw"}, time.Now()))
	f.st, _ = state.Load(dir)

	p := &Proxy{Store: s, State: f.st, Audit: state.NewAudit(dir), Transport: f.upstream.Client().Transport}
	f.proxy = httptest.NewServer(p)
	t.Cleanup(f.proxy.Close)
	return f
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func get(t *testing.T, url string, header map[string]string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

func TestHeaderInjectionAndRedaction(t *testing.T) {
	f := setup(t, store.Binding{Header: "x-api-key"}, "your key is sk-real-123, ok")
	resp, body := get(t, f.proxy.URL+"/demo/API_KEY/v1/messages?a=1",
		map[string]string{"x-api-key": "placeholder", "Authorization": "Bearer leak"})

	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if got := f.lastReq.Header.Get("x-api-key"); got != "sk-real-123" {
		t.Fatalf("upstream got key %q", got)
	}
	if f.lastReq.Header.Get("Authorization") != "" {
		t.Fatal("client Authorization header was forwarded")
	}
	if f.lastReq.URL.Path != "/v1/messages" || f.lastReq.URL.RawQuery != "a=1" {
		t.Fatalf("upstream path %q query %q", f.lastReq.URL.Path, f.lastReq.URL.RawQuery)
	}
	if strings.Contains(body, "sk-real-123") || body != "your key is ***, ok" {
		t.Fatalf("body not masked: %q", body)
	}
	if resp.Header.Get("X-Echo") != "***" {
		t.Fatalf("header not masked: %q", resp.Header.Get("X-Echo"))
	}
}

// A client that asks for gzip (Node fetch does) must still get a masked body.
func TestCompressedUpstreamIsMasked(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := []byte("key sk-real-123 in a compressed body")
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(w)
			gz.Write(body)
			gz.Close()
			return
		}
		w.Write(body)
	}))
	defer upstream.Close()

	dir := t.TempDir()
	key, _ := store.NewKey()
	s, _ := store.Open(dir, key)
	must(t, s.Create(store.Secret{Project: "demo", Name: "API_KEY", Tier: store.TierProxy, Value: "sk-real-123",
		Binding: &store.Binding{Host: strings.TrimPrefix(upstream.URL, "https://"), Header: "x-api-key"}}, time.Now()))
	st, _ := state.Load(dir)
	p := httptest.NewServer(&Proxy{Store: s, State: st, Audit: state.NewAudit(dir), Transport: upstream.Client().Transport})
	defer p.Close()

	// Setting Accept-Encoding by hand turns off the Go client's own decompression.
	resp, body := get(t, p.URL+"/demo/API_KEY/x", map[string]string{"Accept-Encoding": "gzip, br"})
	if resp.Header.Get("Content-Encoding") != "" {
		t.Fatalf("response still compressed: %q", resp.Header.Get("Content-Encoding"))
	}
	if body != "key *** in a compressed body" {
		t.Fatalf("body: %q", body)
	}
}

func TestFormatAndQuery(t *testing.T) {
	f := setup(t, store.Binding{Header: "Authorization", Format: "Bearer {}"}, "ok")
	get(t, f.proxy.URL+"/demo/API_KEY/x", nil)
	if got := f.lastReq.Header.Get("Authorization"); got != "Bearer sk-real-123" {
		t.Fatalf("got %q", got)
	}

	f = setup(t, store.Binding{Query: "key"}, "ok")
	get(t, f.proxy.URL+"/demo/API_KEY/maps?q=x&key=fake", nil)
	if got := f.lastReq.URL.Query().Get("key"); got != "sk-real-123" {
		t.Fatalf("query key %q", got)
	}
}

func TestRefusals(t *testing.T) {
	f := setup(t, store.Binding{Header: "x-api-key"}, "ok")
	cases := map[string]int{
		"/demo/DB_PASSWORD/x": http.StatusForbidden, // run tier never goes through the proxy
		"/demo/MISSING/x":     http.StatusNotFound,
		"/bad path":           http.StatusBadRequest,
	}
	for path, want := range cases {
		if resp, _ := get(t, f.proxy.URL+path, nil); resp.StatusCode != want {
			t.Errorf("%s: status %d, want %d", path, resp.StatusCode, want)
		}
	}
	must(t, f.st.SetLocked("demo", true, time.Now()))
	if resp, _ := get(t, f.proxy.URL+"/demo/API_KEY/x", nil); resp.StatusCode != http.StatusForbidden {
		t.Errorf("locked project: status %d", resp.StatusCode)
	}
}

// recorder is a plain-HTTP upstream that remembers the last request.
type recorder struct {
	srv     *httptest.Server
	path    string
	auth    string
	body    []byte
	encName string
}

func newRecorder(t *testing.T, reply func(r *http.Request) string) *recorder {
	t.Helper()
	rec := &recorder{}
	rec.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.path, rec.auth, rec.encName = r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Encoding")
		rec.body, _ = io.ReadAll(r.Body)
		io.WriteString(w, reply(r))
	}))
	t.Cleanup(rec.srv.Close)
	return rec
}

func (r *recorder) host() string { return strings.TrimPrefix(r.srv.URL, "http://") }

// multiHost serves one secret bound to two plain-HTTP upstreams.
func multiHost(t *testing.T, b store.Binding, a, c *recorder) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	key, _ := store.NewKey()
	s, _ := store.Open(dir, key)
	b.Host, b.ExtraHosts = a.host(), []string{c.host()}
	must(t, s.Create(store.Secret{Project: "user", Name: "GITHUB_TOKEN", Tier: store.TierProxy, Value: "tok-123", Binding: &b}, time.Now()))
	st, _ := state.Load(dir)
	p := httptest.NewServer(&Proxy{Store: s, State: st, Audit: state.NewAudit(dir), Scheme: "http"})
	t.Cleanup(p.Close)
	return p
}

func TestMultiHostRouting(t *testing.T) {
	api := newRecorder(t, func(*http.Request) string { return "api" })
	git := newRecorder(t, func(*http.Request) string { return "git" })
	p := multiHost(t, store.Binding{Header: "Authorization", Format: "Bearer {}"}, api, git)

	if _, body := get(t, p.URL+"/user/GITHUB_TOKEN/repos/o/r", nil); body != "api" || api.path != "/repos/o/r" {
		t.Fatalf("default host: body %q path %q", body, api.path)
	}
	if _, body := get(t, p.URL+"/user/GITHUB_TOKEN/"+git.host()+"/o/r.git/info/refs", nil); body != "git" || git.path != "/o/r.git/info/refs" {
		t.Fatalf("second host: body %q path %q", body, git.path)
	}
	if git.auth != "Bearer tok-123" {
		t.Fatalf("second host got auth %q", git.auth)
	}
	// Naming the default host works too; an unbound host is just a path on the default host.
	if _, body := get(t, p.URL+"/user/GITHUB_TOKEN/"+api.host()+"/x", nil); body != "api" || api.path != "/x" {
		t.Fatalf("default host by name: %q %q", body, api.path)
	}
	if _, body := get(t, p.URL+"/user/GITHUB_TOKEN/evil.example.com/x", nil); body != "api" || api.path != "/evil.example.com/x" {
		t.Fatalf("unbound host: %q %q", body, api.path)
	}
}

// A one-host binding never strips a path segment, even one named like its host.
func TestSingleHostPathUnchanged(t *testing.T) {
	f := setup(t, store.Binding{Header: "x-api-key"}, "ok")
	host := strings.TrimPrefix(f.upstream.URL, "https://")
	get(t, f.proxy.URL+"/demo/API_KEY/"+host+"/x", nil)
	if f.lastReq.URL.Path != "/"+host+"/x" {
		t.Fatalf("path %q", f.lastReq.URL.Path)
	}
}

func TestBasicAuthAndMasking(t *testing.T) {
	// The upstream echoes the credential back, raw and in its header form.
	echo := func(r *http.Request) string { return "auth=" + r.Header.Get("Authorization") + " raw=tok-123" }
	api := newRecorder(t, echo)
	git := newRecorder(t, echo)
	p := multiHost(t, store.Binding{Header: "Authorization", Basic: "blackstonecan"}, api, git)

	_, body := get(t, p.URL+"/user/GITHUB_TOKEN/"+git.host()+"/o/r.git/info/refs", map[string]string{"Authorization": "placeholder"})
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("blackstonecan:tok-123"))
	if git.auth != want {
		t.Fatalf("upstream auth %q, want %q", git.auth, want)
	}
	if strings.Contains(body, "tok-123") || strings.Contains(body, want[len("Basic "):]) || body != "auth=Basic *** raw=***" {
		t.Fatalf("body not masked: %q", body)
	}
}

// git push sends a gzip-compressed POST body; it must reach the upstream unchanged.
func TestCompressedRequestBody(t *testing.T) {
	api := newRecorder(t, func(*http.Request) string { return "ok" })
	git := newRecorder(t, func(*http.Request) string { return "ok" })
	p := multiHost(t, store.Binding{Header: "Authorization", Basic: "blackstonecan"}, api, git)

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write([]byte("0000PACK binary \x00\x01\x02 data"))
	gz.Close()
	sent := buf.Bytes()
	req, _ := http.NewRequest("POST", p.URL+"/user/GITHUB_TOKEN/"+git.host()+"/o/r.git/git-receive-pack", bytes.NewReader(sent))
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Content-Type", "application/x-git-receive-pack-request")
	resp, err := http.DefaultClient.Do(req)
	must(t, err)
	resp.Body.Close()
	if !bytes.Equal(git.body, sent) || git.encName != "gzip" || git.path != "/o/r.git/git-receive-pack" {
		t.Fatalf("body changed: %d bytes (sent %d), encoding %q, path %q", len(git.body), len(sent), git.encName, git.path)
	}
}

// A project that falls back to a user-scope secret gets /user/NAME as its base
// URL, so `secret lock user` blocks every use of it through the proxy.
func TestUserScopeLock(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Header.Get("Authorization"))
	}))
	defer upstream.Close()
	dir := t.TempDir()
	key, _ := store.NewKey()
	s, _ := store.Open(dir, key)
	must(t, s.Create(store.Secret{Project: store.UserProject, Name: "GITHUB_TOKEN", Tier: store.TierProxy, Value: "gh-user",
		Binding: &store.Binding{Host: strings.TrimPrefix(upstream.URL, "https://"), Header: "Authorization", Format: "Bearer {}"}}, time.Now()))
	st, _ := state.Load(dir)
	p := httptest.NewServer(&Proxy{Store: s, State: st, Audit: state.NewAudit(dir), Transport: upstream.Client().Transport})
	defer p.Close()

	if resp, body := get(t, p.URL+"/user/GITHUB_TOKEN/x", nil); resp.StatusCode != 200 || body != "Bearer ***" {
		t.Fatalf("user-scope proxy: %d %q", resp.StatusCode, body)
	}
	must(t, st.SetLocked(store.UserProject, true, time.Now()))
	if resp, _ := get(t, p.URL+"/user/GITHUB_TOKEN/x", nil); resp.StatusCode != http.StatusForbidden {
		t.Errorf("locked user scope: status %d", resp.StatusCode)
	}
}
