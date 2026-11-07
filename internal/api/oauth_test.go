package api

import (
	"encoding/base64"
	"fmt"
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

// tokenServer is a fake token endpoint (/token) and revocation endpoint
// (/revoke) that records the forms it received.
type tokenServer struct {
	srv     *httptest.Server
	forms   []map[string]string
	revoked []string
	reply   func(form map[string]string) (int, string)
}

func newTokenServer(t *testing.T) *tokenServer {
	t.Helper()
	ts := &tokenServer{}
	ts.reply = func(map[string]string) (int, string) {
		return 200, `{"access_token":"at","refresh_token":"rt-1","expires_in":3599,"scope":"a b openid email","id_token":"` + idToken("agent@example.com") + `"}`
	}
	ts.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		form := map[string]string{}
		for k := range r.PostForm {
			form[k] = r.PostForm.Get(k)
		}
		if r.URL.Path == "/revoke" {
			ts.revoked = append(ts.revoked, form["token"])
			return
		}
		ts.forms = append(ts.forms, form)
		code, body := ts.reply(form)
		w.WriteHeader(code)
		io.WriteString(w, body)
	}))
	t.Cleanup(ts.srv.Close)
	return ts
}

func (ts *tokenServer) host() string { return strings.TrimPrefix(ts.srv.URL, "https://") }

func idToken(email string) string {
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"sub":"1","email":%q}`, email)))
	return "eyJhbGciOiJub25lIn0." + payload + ".sig"
}

// startOAuthServer serves the API with an HTTP client that trusts the fake
// token endpoint, and stores the client id and client secret of project mail.
func startOAuthServer(t *testing.T, ts *tokenServer) (*Client, *store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	key, _ := store.NewKey()
	s, _ := store.Open(dir, key)
	st, _ := state.Load(dir)
	srv := &Server{Store: s, State: st, Audit: state.NewAudit(dir), AllowUID: os.Getuid(), ProxyAddr: "127.0.0.1:7777", HTTP: ts.srv.Client()}
	sock := filepath.Join(dir, "api.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: srv.Handler(), ConnContext: ConnContext}
	go hs.Serve(ln)
	t.Cleanup(func() { hs.Close() })
	c := NewClient(sock)
	must(t, c.Set(SetRequest{Project: "mail", Name: "CID", Tier: store.TierPublic, Value: "cid.apps"}))
	must(t, c.Set(SetRequest{Project: "mail", Name: "CSECRET", Tier: store.TierProxy, Value: "cs-1",
		Binding: &store.Binding{Host: ts.host(), Header: "Authorization", Basic: "CID"}}))
	return c, s, dir
}

func exchangeReq(ts *tokenServer) OAuthExchangeRequest {
	return OAuthExchangeRequest{
		Project: "mail", Name: "GMAIL_TOKEN",
		Binding:      &store.Binding{Host: "gmail.googleapis.com", OAuth: &store.OAuth{TokenURL: ts.srv.URL + "/token", ClientID: "CID", ClientSecret: "CSECRET"}},
		Code:         "code-1", RedirectURI: "http://127.0.0.1:4242", CodeVerifier: "verifier-1",
		Scopes:       []string{"a", "b"}, Account: "Agent@Example.com", RevokeURL: ts.srv.URL + "/revoke",
	}
}

func TestOAuthExchangeStoresRefreshToken(t *testing.T) {
	ts := newTokenServer(t)
	c, s, dir := startOAuthServer(t, ts)
	res, err := c.OAuthExchange(exchangeReq(ts))
	must(t, err)
	if res.Stored != "mail/GMAIL_TOKEN" || res.Account != "agent@example.com" || strings.Join(res.Scopes, " ") != "a b openid email" {
		t.Fatalf("result: %+v", res)
	}
	form := ts.forms[0]
	if form["grant_type"] != "authorization_code" || form["code"] != "code-1" || form["code_verifier"] != "verifier-1" ||
		form["redirect_uri"] != "http://127.0.0.1:4242" || form["client_id"] != "cid.apps" || form["client_secret"] != "cs-1" {
		t.Fatalf("token form: %v", form)
	}
	sec, err := s.Get("mail", "GMAIL_TOKEN")
	must(t, err)
	if sec.Tier != store.TierProxy || sec.Value != "rt-1" || sec.Binding.OAuth == nil || sec.Binding.Host != "gmail.googleapis.com" {
		t.Fatalf("stored: %+v", sec)
	}
	// The CLI sees no token, and neither does the audit log.
	list, _ := c.List("mail")
	for _, in := range list {
		if in.Name == "GMAIL_TOKEN" && in.Value != "" {
			t.Fatal("list shows the refresh token")
		}
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "audit.log"))
	if strings.Contains(string(raw), "rt-1") || strings.Contains(string(raw), "cs-1") || !strings.Contains(string(raw), `"op":"oauth"`) {
		t.Fatalf("audit: %s", raw)
	}
	// Second time: the name exists, no exchange happens.
	if _, err := c.OAuthExchange(exchangeReq(ts)); err == nil || !strings.Contains(err.Error(), "already exists") || len(ts.forms) != 1 {
		t.Fatalf("exists: %v (%d exchanges)", err, len(ts.forms))
	}
}

func TestOAuthExchangeChecksAndRevokes(t *testing.T) {
	cases := map[string]struct {
		body string
		want string
	}{
		"no refresh token": {`{"access_token":"at-only","scope":"a b"}`, "no refresh token"},
		"missing scope":    {`{"access_token":"at","refresh_token":"rt-x","scope":"a openid email","id_token":"` + idToken("agent@example.com") + `"}`, "scopes not granted: b"},
		"wrong account":    {`{"access_token":"at","refresh_token":"rt-x","scope":"a b openid email","id_token":"` + idToken("other@example.com") + `"}`, "came from other@example.com"},
		"no id token":      {`{"access_token":"at","refresh_token":"rt-x","scope":"a b"}`, "cannot check the account"},
	}
	for name, tc := range cases {
		ts := newTokenServer(t)
		ts.reply = func(map[string]string) (int, string) { return 200, tc.body }
		c, s, _ := startOAuthServer(t, ts)
		_, err := c.OAuthExchange(exchangeReq(ts))
		if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "revoked") || !strings.Contains(err.Error(), "nothing was stored") {
			t.Errorf("%s: %v", name, err)
		}
		if err != nil && (strings.Contains(err.Error(), "rt-x") || strings.Contains(err.Error(), "at-only")) {
			t.Errorf("%s: error leaks a token: %v", name, err)
		}
		if len(ts.revoked) != 1 {
			t.Errorf("%s: revoked %v", name, ts.revoked)
		}
		if _, err := s.Get("mail", "GMAIL_TOKEN"); err == nil {
			t.Errorf("%s: a secret was stored", name)
		}
	}
}

func TestOAuthExchangeErrors(t *testing.T) {
	ts := newTokenServer(t)
	ts.reply = func(map[string]string) (int, string) {
		return 400, `{"error":"invalid_grant","error_description":"Bad Request BODY-TEXT"}`
	}
	c, s, _ := startOAuthServer(t, ts)
	_, err := c.OAuthExchange(exchangeReq(ts))
	if err == nil || !strings.Contains(err.Error(), "invalid_grant") || strings.Contains(err.Error(), "BODY-TEXT") {
		t.Fatalf("refused code: %v", err)
	}
	// The client secret must be proxy-tier and bound to the token host.
	must(t, s.Rebind("mail", "CSECRET", store.TierProxy, "", &store.Binding{Host: "elsewhere.example.com", Header: "x"}, time.Now()))
	if _, err := c.OAuthExchange(exchangeReq(ts)); err == nil || !strings.Contains(err.Error(), "must be a proxy-tier secret bound to") {
		t.Fatalf("client secret binding: %v", err)
	}
	// A bad binding is refused before any network call.
	req := exchangeReq(ts)
	req.Binding.OAuth.TokenURL = "http://plain/token"
	if _, err := c.OAuthExchange(req); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("http token url: %v", err)
	}
	if len(ts.forms) != 1 {
		t.Fatalf("%d exchanges, want 1", len(ts.forms))
	}
}
