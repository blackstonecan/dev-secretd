package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blackstonecan/dev-secretd/internal/state"
	"github.com/blackstonecan/dev-secretd/internal/store"
)

// oauthFixture is one TLS server that plays the token endpoint (/token) and
// the API (everything else), so one host serves both.
type oauthFixture struct {
	srv      *httptest.Server
	proxy    *httptest.Server
	store    *store.Store
	dir      string
	refreshN atomic.Int32 // token endpoint calls
	apiAuth  []string     // Authorization headers the API saw
	apiBody  string       // last API request body
	// tokenReply decides what the token endpoint answers (status, JSON).
	tokenReply func(form map[string]string, n int) (int, string)
	// apiReply decides what the API answers for a Bearer token.
	apiReply func(bearer string) (int, string)
}

func newOAuthFixture(t *testing.T) *oauthFixture {
	t.Helper()
	f := &oauthFixture{}
	f.tokenReply = func(form map[string]string, n int) (int, string) {
		return 200, fmt.Sprintf(`{"access_token":"at-%d","expires_in":3600,"token_type":"Bearer"}`, n)
	}
	f.apiReply = func(bearer string) (int, string) { return 200, "hello " + bearer }
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			r.ParseForm()
			form := map[string]string{}
			for k := range r.PostForm {
				form[k] = r.PostForm.Get(k)
			}
			n := int(f.refreshN.Add(1))
			code, body := f.tokenReply(form, n)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			io.WriteString(w, body)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		f.apiBody = string(raw)
		auth := r.Header.Get("Authorization")
		f.apiAuth = append(f.apiAuth, auth)
		code, body := f.apiReply(strings.TrimPrefix(auth, "Bearer "))
		w.Header().Set("X-Echo", auth)
		w.WriteHeader(code)
		io.WriteString(w, body)
	}))
	t.Cleanup(f.srv.Close)

	f.dir = t.TempDir()
	key, _ := store.NewKey()
	f.store, _ = store.Open(f.dir, key)
	host := strings.TrimPrefix(f.srv.URL, "https://")
	must(t, f.store.SetPublic("mail", "GMAIL_CLIENT_ID", "cid.apps", time.Now()))
	must(t, f.store.Create(store.Secret{Project: "mail", Name: "GMAIL_CLIENT_SECRET", Tier: store.TierProxy, Value: "cs-secret",
		Binding: &store.Binding{Host: host, Header: "Authorization", Basic: "GMAIL_CLIENT_ID"}}, time.Now()))
	must(t, f.store.Create(store.Secret{Project: "mail", Name: "GMAIL_REFRESH", Tier: store.TierProxy, Value: "rt-refresh-1",
		Binding: &store.Binding{Host: host, OAuth: &store.OAuth{TokenURL: f.srv.URL + "/token", ClientID: "GMAIL_CLIENT_ID", ClientSecret: "GMAIL_CLIENT_SECRET"}}}, time.Now()))
	st, _ := state.Load(f.dir)
	p := &Proxy{Store: f.store, State: st, Audit: state.NewAudit(f.dir), Transport: f.srv.Client().Transport}
	f.proxy = httptest.NewServer(p)
	t.Cleanup(f.proxy.Close)
	return f
}

func (f *oauthFixture) audit(t *testing.T) string {
	t.Helper()
	raw, _ := os.ReadFile(filepath.Join(f.dir, "audit.log"))
	return string(raw)
}

func TestOAuthRefreshAndBearer(t *testing.T) {
	f := newOAuthFixture(t)
	var seen map[string]string
	f.tokenReply = func(form map[string]string, n int) (int, string) {
		seen = form
		return 200, `{"access_token":"at-1","expires_in":3600}`
	}
	resp, body := get(t, f.proxy.URL+"/mail/GMAIL_REFRESH/gmail/v1/users/me/profile", map[string]string{"Authorization": "Bearer placeholder"})
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if seen["grant_type"] != "refresh_token" || seen["refresh_token"] != "rt-refresh-1" || seen["client_id"] != "cid.apps" || seen["client_secret"] != "cs-secret" {
		t.Fatalf("token request form: %v", seen)
	}
	if len(f.apiAuth) != 1 || f.apiAuth[0] != "Bearer at-1" {
		t.Fatalf("API got %v", f.apiAuth)
	}
	// The access token is masked in the body and the headers.
	if body != "hello ***" || resp.Header.Get("X-Echo") != "Bearer ***" {
		t.Fatalf("not masked: body %q header %q", body, resp.Header.Get("X-Echo"))
	}
	// A second call uses the cached token: no new refresh.
	get(t, f.proxy.URL+"/mail/GMAIL_REFRESH/x", nil)
	if f.refreshN.Load() != 1 || len(f.apiAuth) != 2 || f.apiAuth[1] != "Bearer at-1" {
		t.Fatalf("cache: %d refreshes, auth %v", f.refreshN.Load(), f.apiAuth)
	}
	log := f.audit(t)
	if strings.Contains(log, "at-1") || strings.Contains(log, "rt-refresh") || strings.Contains(log, "cs-secret") {
		t.Fatalf("audit log has a token: %s", log)
	}
	if !strings.Contains(log, `"op":"oauth"`) {
		t.Fatalf("no oauth audit event: %s", log)
	}
}

// A 401 from the API refreshes the token once and sends the request again,
// with its body.
func TestOAuthRetryOn401(t *testing.T) {
	f := newOAuthFixture(t)
	f.apiReply = func(bearer string) (int, string) {
		if bearer == "at-1" {
			return 401, `{"error":"invalid token"}`
		}
		return 200, "sent"
	}
	req, _ := http.NewRequest("POST", f.proxy.URL+"/mail/GMAIL_REFRESH/gmail/v1/users/me/messages/send", strings.NewReader(`{"raw":"abc"}`))
	resp, err := http.DefaultClient.Do(req)
	must(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "sent" {
		t.Fatalf("retry: %d %s", resp.StatusCode, body)
	}
	if f.refreshN.Load() != 2 || len(f.apiAuth) != 2 || f.apiAuth[0] != "Bearer at-1" || f.apiAuth[1] != "Bearer at-2" {
		t.Fatalf("refreshes %d, auth %v", f.refreshN.Load(), f.apiAuth)
	}
	if f.apiBody != `{"raw":"abc"}` {
		t.Fatalf("retried body %q", f.apiBody)
	}
	// Both tokens are masked: the old one may still appear in a response.
	f.apiReply = func(string) (int, string) { return 200, "old at-1 new at-2" }
	if _, body := get(t, f.proxy.URL+"/mail/GMAIL_REFRESH/x", nil); body != "old *** new ***" {
		t.Fatalf("masks: %q", body)
	}
}

// A 401 that stays a 401 after the refresh is passed to the client, once.
func TestOAuthRetryOnlyOnce(t *testing.T) {
	f := newOAuthFixture(t)
	f.apiReply = func(string) (int, string) { return 401, "no" }
	resp, _ := get(t, f.proxy.URL+"/mail/GMAIL_REFRESH/x", nil)
	if resp.StatusCode != 401 || f.refreshN.Load() != 2 || len(f.apiAuth) != 2 {
		t.Fatalf("status %d, refreshes %d, calls %d", resp.StatusCode, f.refreshN.Load(), len(f.apiAuth))
	}
}

func TestOAuthInvalidGrant(t *testing.T) {
	f := newOAuthFixture(t)
	f.tokenReply = func(map[string]string, int) (int, string) {
		return 400, `{"error":"invalid_grant","error_description":"Token has been expired or revoked. SECRET-BODY"}`
	}
	resp, body := get(t, f.proxy.URL+"/mail/GMAIL_REFRESH/x", nil)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	for _, want := range []string{"mail/GMAIL_REFRESH", "invalid_grant", "consent again"} {
		if !strings.Contains(body, want) {
			t.Errorf("error lacks %q: %s", want, body)
		}
	}
	for _, leak := range []string{"SECRET-BODY", "/token", "rt-refresh", "cs-secret"} {
		if strings.Contains(body, leak) {
			t.Errorf("error leaks %q: %s", leak, body)
		}
	}
	if len(f.apiAuth) != 0 {
		t.Fatal("API was called without a token")
	}
	if log := f.audit(t); !strings.Contains(log, "invalid_grant") || strings.Contains(log, "SECRET-BODY") {
		t.Fatalf("audit: %s", log)
	}
}

// The client secret must be a proxy-tier secret bound to the token host.
func TestOAuthClientSecretMustBeProxyTier(t *testing.T) {
	f := newOAuthFixture(t)
	must(t, f.store.Rebind("mail", "GMAIL_CLIENT_SECRET", store.TierRun, store.KindEnv, nil, time.Now()))
	resp, body := get(t, f.proxy.URL+"/mail/GMAIL_REFRESH/x", nil)
	if resp.StatusCode != http.StatusInternalServerError || !strings.Contains(body, "must be a proxy-tier secret bound to") || strings.Contains(body, "cs-secret") {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if f.refreshN.Load() != 0 {
		t.Fatal("token endpoint was called")
	}
	// Bound to another host: refused too.
	must(t, f.store.Rebind("mail", "GMAIL_CLIENT_SECRET", store.TierProxy, "", &store.Binding{Host: "other.example.com", Header: "x"}, time.Now()))
	if resp, _ := get(t, f.proxy.URL+"/mail/GMAIL_REFRESH/x", nil); resp.StatusCode != http.StatusInternalServerError || f.refreshN.Load() != 0 {
		t.Fatalf("other host: %d", resp.StatusCode)
	}
}

// A rotated refresh token drops the cached access token.
func TestOAuthRotateInvalidatesCache(t *testing.T) {
	f := newOAuthFixture(t)
	get(t, f.proxy.URL+"/mail/GMAIL_REFRESH/x", nil)
	must(t, f.store.Rotate("mail", "GMAIL_REFRESH", "rt-refresh-2", time.Now()))
	var seen map[string]string
	f.tokenReply = func(form map[string]string, n int) (int, string) {
		seen = form
		return 200, `{"access_token":"at-new","expires_in":3600}`
	}
	get(t, f.proxy.URL+"/mail/GMAIL_REFRESH/x", nil)
	if seen["refresh_token"] != "rt-refresh-2" || f.apiAuth[1] != "Bearer at-new" {
		t.Fatalf("after rotate: form %v auth %v", seen, f.apiAuth)
	}
}

// A short expires_in is refreshed early.
func TestOAuthExpiry(t *testing.T) {
	f := newOAuthFixture(t)
	f.tokenReply = func(_ map[string]string, n int) (int, string) {
		return 200, fmt.Sprintf(`{"access_token":"at-%d","expires_in":1}`, n)
	}
	get(t, f.proxy.URL+"/mail/GMAIL_REFRESH/x", nil)
	time.Sleep(600 * time.Millisecond) // half of 1s has passed
	get(t, f.proxy.URL+"/mail/GMAIL_REFRESH/x", nil)
	if f.refreshN.Load() != 2 {
		t.Fatalf("refreshes %d", f.refreshN.Load())
	}
}

func TestOAuthStoreValidation(t *testing.T) {
	ok := store.Binding{Host: "gmail.googleapis.com", OAuth: &store.OAuth{TokenURL: "https://oauth2.googleapis.com/token", ClientID: "CID"}}
	sec := store.Secret{Project: "p", Name: "N", Tier: store.TierProxy, Value: "v", Binding: &ok}
	must(t, sec.Validate())
	bad := map[string]store.Binding{
		"http token url": {Host: "a.com", OAuth: &store.OAuth{TokenURL: "http://x/token", ClientID: "CID"}},
		"client id":      {Host: "a.com", OAuth: &store.OAuth{TokenURL: "https://x/token", ClientID: "cid"}},
		"with header":    {Host: "a.com", Header: "x", OAuth: &store.OAuth{TokenURL: "https://x/token", ClientID: "CID"}},
		"with basic":     {Host: "a.com", BasicAuth: true, OAuth: &store.OAuth{TokenURL: "https://x/token", ClientID: "CID"}},
	}
	for name, b := range bad {
		b := b
		if err := (&store.Secret{Project: "p", Name: "N", Tier: store.TierProxy, Value: "v", Binding: &b}).Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	raw, _ := json.Marshal(ok)
	if !strings.Contains(string(raw), `"token_url"`) {
		t.Fatalf("json: %s", raw)
	}
}
