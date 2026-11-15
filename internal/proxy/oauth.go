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
	mu sync.Mutex
	// stored is the value of the secret in the store that this entry belongs to.
	stored string
	// refresh is the refresh token for the next refresh: stored, or a newer one
	// that the token endpoint sent (rotation) and the store has not taken yet.
	refresh  string
	access   string
	previous string // the access token before the last refresh, still masked
	expiry   time.Time
	saveTry  time.Time // the last attempt to save a rotated refresh token
}

// A rotated refresh token that could not be saved is tried again after this
// long, on the next request. A variable for the tests.
var saveRetry = 30 * time.Second

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
	if sec.Value != e.stored {
		// Either the secret was replaced (root rotated it, or this is the first
		// use), or the caller read it before this proxy saved a rotated refresh
		// token. The store says which.
		cur, err := p.Store.Get(sec.Project, sec.Name)
		if err != nil {
			return "", &oauthError{http.StatusInternalServerError, sec.Key() + ": store error"}
		}
		if cur.Value != e.stored {
			// Replaced: forget the old tokens.
			e.stored, e.refresh, e.access, e.previous, e.expiry = cur.Value, cur.Value, "", "", time.Time{}
		}
	}
	if e.refresh != e.stored && time.Since(e.saveTry) >= saveRetry {
		p.saveRefresh(sec, e)
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
	if tok.Refresh != "" && tok.Refresh != e.refresh {
		// The provider rotates refresh tokens: the one just used is dead. Keep
		// the new one in memory first, so a failed save does not lose it while
		// the daemon runs.
		e.refresh = tok.Refresh
		p.saveRefresh(sec, e)
	}
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

// saveRefresh writes a rotated refresh token to the store. The caller holds
// e.mu. A failure is logged and tried again later: the token in memory keeps
// the proxy working, but a daemon restart before a successful save needs a
// new consent.
func (p *Proxy) saveRefresh(sec *store.Secret, e *tokenEntry) {
	e.saveTry = time.Now()
	ev := state.Event{Op: "oauth", Project: sec.Project, Name: sec.Name, Detail: "rotated refresh token saved"}
	switch err := p.Store.ReplaceRefreshToken(sec.Project, sec.Name, e.stored, e.refresh, e.saveTry); {
	case err == nil:
		e.stored = e.refresh
	case errors.Is(err, store.ErrChanged), errors.Is(err, store.ErrNotFound):
		// Root rotated or removed the secret during the refresh. Its value wins;
		// the next request reads it.
		ev.Detail, ev.Error = "rotated refresh token dropped", err.Error()
	default:
		ev.Detail, ev.Error = "rotated refresh token NOT saved (will try again)", err.Error()
	}
	p.Audit.Log(ev)
}

// knownTokens returns the tokens that may appear in a response of sec: the
// access token, the one before it, and a rotated refresh token.
func (p *Proxy) knownTokens(sec *store.Secret) []string {
	e := p.tokens.entry(sec.Key())
	e.mu.Lock()
	defer e.mu.Unlock()
	return []string{e.access, e.previous, e.refresh}
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
