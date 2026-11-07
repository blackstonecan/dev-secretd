package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/blackstonecan/dev-secretd/internal/oauth"
	"github.com/blackstonecan/dev-secretd/internal/state"
	"github.com/blackstonecan/dev-secretd/internal/store"
)

// Access tokens are refreshed this long before they expire.
const refreshEarly = 60 * time.Second

// maxRetryBody is the largest request body the proxy keeps in memory so that
// it can send the request again after a 401. Larger bodies are streamed and
// never retried.
const maxRetryBody = 16 << 20

// tokenCache holds one access token per refresh-token secret.
type tokenCache struct {
	mu      sync.Mutex
	entries map[string]*tokenEntry
}

type tokenEntry struct {
	mu       sync.Mutex
	refresh  string // the refresh token the access token came from
	access   string
	previous string // the access token before the last refresh, still masked
	expiry   time.Time
}

func (c *tokenCache) entry(key string) *tokenEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = map[string]*tokenEntry{}
	}
	e, ok := c.entries[key]
	if !ok {
		e = &tokenEntry{}
		c.entries[key] = e
	}
	return e
}

// oauthError is a failure of the proxy itself, before or between upstream
// calls: the token could not be refreshed, or the binding's parts are
// missing. The message names the secret and never holds a token.
type oauthError struct {
	status int
	msg    string
}

func (e *oauthError) Error() string { return e.msg }

// accessToken returns a valid access token for sec, refreshing it when it is
// missing, about to expire, or when force says the upstream refused it.
func (p *Proxy) accessToken(ctx context.Context, sec *store.Secret, force bool) (string, error) {
	e := p.tokens.entry(sec.Key())
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.refresh != sec.Value {
		// Rotated: forget the old access token.
		e.refresh, e.access, e.previous, e.expiry = sec.Value, "", "", time.Time{}
	}
	if !force && e.access != "" && time.Now().Before(e.expiry) {
		return e.access, nil
	}
	o := sec.Binding.OAuth
	clientID, clientSecret, err := p.Store.OAuthClient(sec.Project, o)
	if err != nil {
		return "", &oauthError{http.StatusInternalServerError, sec.Key() + ": " + err.Error()}
	}
	secretValue := ""
	if clientSecret != nil {
		if p.State.IsLocked(clientSecret.Project) {
			return "", &oauthError{http.StatusForbidden, fmt.Sprintf("%s: project %s is locked", sec.Key(), clientSecret.Project)}
		}
		secretValue = clientSecret.Value
	}
	tok, err := oauth.Refresh(ctx, p.httpClient(), o.TokenURL, clientID, secretValue, e.refresh)
	ev := state.Event{Op: "oauth", Project: sec.Project, Name: sec.Name, Detail: "refresh " + o.TokenHost()}
	if err != nil {
		ev.Error = err.Error()
		p.Audit.Log(ev)
		msg := fmt.Sprintf("%s: cannot refresh the access token (%v)", sec.Key(), err)
		if oauth.IsInvalidGrant(err) {
			msg += ": the refresh token was revoked or expired; give the consent again (`secret oauth login`, or the project's consent script) and replace the secret"
		}
		return "", &oauthError{http.StatusBadGateway, msg}
	}
	p.Audit.Log(ev)
	ttl := time.Duration(tok.ExpiresIn) * time.Second
	switch {
	case ttl <= 0:
		ttl = 5 * time.Minute
	case ttl > 2*refreshEarly:
		ttl -= refreshEarly
	default:
		ttl /= 2
	}
	e.previous, e.access, e.expiry = e.access, tok.Access, time.Now().Add(ttl)
	return e.access, nil
}

// knownTokens returns the access tokens that may appear in a response of
// sec: the current one and the one before it.
func (p *Proxy) knownTokens(sec *store.Secret) []string {
	e := p.tokens.entry(sec.Key())
	e.mu.Lock()
	defer e.mu.Unlock()
	return []string{e.access, e.previous}
}

func (p *Proxy) httpClient() *http.Client {
	return &http.Client{Transport: p.Transport, Timeout: 30 * time.Second}
}

// oauthTransport adds "Authorization: Bearer <access>" to each upstream
// request. On a 401 it refreshes the token once and sends the request once
// more, when the body can be sent again.
type oauthTransport struct {
	p    *Proxy
	sec  *store.Secret
	base http.RoundTripper
}

func (t *oauthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	tok, err := t.p.accessToken(req.Context(), t.sec, false)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := base.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}
	hasBody := req.Body != nil && req.Body != http.NoBody
	if hasBody && req.GetBody == nil {
		return resp, nil
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	tok, err = t.p.accessToken(req.Context(), t.sec, true)
	if err != nil {
		return nil, err
	}
	retry := req.Clone(req.Context())
	if hasBody {
		if retry.Body, err = req.GetBody(); err != nil {
			return nil, err
		}
	}
	retry.Header.Set("Authorization", "Bearer "+tok)
	return base.RoundTrip(retry)
}

// bufferBody keeps a request body in memory, so the request can be sent
// twice. A body over maxRetryBody is streamed instead (no retry).
func bufferBody(req *http.Request) {
	if req.Body == nil || req.Body == http.NoBody {
		return
	}
	data, err := io.ReadAll(io.LimitReader(req.Body, maxRetryBody+1))
	if err != nil || len(data) > maxRetryBody {
		req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(data), req.Body))
		return
	}
	req.Body = io.NopCloser(bytes.NewReader(data))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil }
	req.ContentLength = int64(len(data))
}

// asOAuthError returns the proxy's own error, if err is one.
func asOAuthError(err error) *oauthError {
	var e *oauthError
	if errors.As(err, &e) {
		return e
	}
	return nil
}
