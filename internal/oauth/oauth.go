// Package oauth talks to an OAuth2 token endpoint for the daemon: it turns a
// refresh token into an access token, exchanges an authorization code, and
// revokes a token. Errors never carry a token or the endpoint's body.
package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Token is what a token endpoint answered.
type Token struct {
	Access    string
	Refresh   string // set after an authorization-code exchange, when the provider gives one
	ExpiresIn int    // seconds; 0 when the provider did not say
	Scope     string // space-separated granted scopes, when the provider says
	IDToken   string // OpenID Connect id_token, when the provider gives one
}

// Scopes returns the granted scopes as a list.
func (t *Token) Scopes() []string { return strings.Fields(t.Scope) }

// Error is a token endpoint's refusal: the OAuth error code (invalid_grant,
// invalid_client, ...) or, without one, the HTTP status. The body is never
// kept.
type Error struct {
	Code   string
	Status int
}

func (e *Error) Error() string {
	if e.Code != "" {
		return "token endpoint said " + e.Code
	}
	return fmt.Sprintf("token endpoint answered HTTP %d", e.Status)
}

// IsInvalidGrant says whether the refresh token (or code) was refused: it was
// revoked, expired, or the consent must be given again.
func IsInvalidGrant(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == "invalid_grant"
}

const maxBody = 1 << 20

// Refresh gets a new access token for a refresh token.
func Refresh(ctx context.Context, c *http.Client, tokenURL, clientID, clientSecret, refresh string) (*Token, error) {
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {clientID}}
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	return post(ctx, c, tokenURL, form)
}

// Exchange turns an authorization code (with its PKCE verifier) into tokens.
func Exchange(ctx context.Context, c *http.Client, tokenURL, clientID, clientSecret, code, redirectURI, verifier string) (*Token, error) {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI},
		"client_id": {clientID}, "code_verifier": {verifier}}
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	return post(ctx, c, tokenURL, form)
}

// Revoke tells the provider to forget a token. Providers that have no
// revocation endpoint are skipped by passing an empty URL.
func Revoke(ctx context.Context, c *http.Client, revokeURL, token string) error {
	if revokeURL == "" {
		return errors.New("no revoke URL")
	}
	resp, cancel, err := do(ctx, c, revokeURL, url.Values{"token": {token}})
	if err != nil {
		return err
	}
	defer cancel()
	io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("revoke endpoint answered HTTP %d", resp.StatusCode)
	}
	return nil
}

func post(ctx context.Context, c *http.Client, tokenURL string, form url.Values) (*Token, error) {
	resp, cancel, err := do(ctx, c, tokenURL, form)
	if err != nil {
		return nil, err
	}
	defer cancel()
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("token endpoint: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		var body struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &body)
		return nil, &Error{Code: sanitize(body.Error), Status: resp.StatusCode}
	}
	var body struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
		IDToken      string `json:"id_token"`
	}
	if err := json.Unmarshal(raw, &body); err != nil || body.AccessToken == "" {
		return nil, errors.New("token endpoint answered without an access token")
	}
	return &Token{Access: body.AccessToken, Refresh: body.RefreshToken, ExpiresIn: body.ExpiresIn, Scope: body.Scope, IDToken: body.IDToken}, nil
}

// do sends the form and returns the response with the cancel function of its
// timeout. The caller calls cancel after it has read the body: the body read
// runs under the same context, so a cancel before the read ends the read with
// "context canceled" (this was a bug until 2026-11-08).
func do(ctx context.Context, c *http.Client, endpoint string, form url.Values) (*http.Response, context.CancelFunc, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" {
		return nil, nil, errors.New("token endpoint must be an https URL")
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		cancel()
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		cancel()
		// A transport error can quote the URL; the host is enough.
		return nil, nil, fmt.Errorf("cannot reach the token endpoint at %s", u.Host)
	}
	return resp, cancel, nil
}

// sanitize keeps an OAuth error code only if it looks like one.
func sanitize(code string) string {
	if len(code) > 40 {
		return ""
	}
	for _, r := range code {
		if !(r >= 'a' && r <= 'z' || r == '_') {
			return ""
		}
	}
	return code
}

// IDTokenEmail reads the email claim of an OpenID Connect id_token. The
// token came straight from the token endpoint over TLS, so its signature is
// not checked here.
func IDTokenEmail(idToken string) (string, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return "", errors.New("id_token is not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("id_token payload is not base64url")
	}
	var claims struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil || claims.Email == "" {
		return "", errors.New("id_token has no email claim (ask for the openid and email scopes)")
	}
	return strings.ToLower(claims.Email), nil
}
