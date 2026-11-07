package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/blackstonecan/dev-secretd/internal/oauth"
	"github.com/blackstonecan/dev-secretd/internal/store"
)

// oauthExchange finishes a consent that `secret oauth login` started: the
// daemon exchanges the code, checks the grant, and stores the refresh token.
// The CLI only ever sees whether it worked.
func (s *Server) oauthExchange(w http.ResponseWriter, r *http.Request) {
	var req OAuthExchangeRequest
	if !readJSON(w, r, &req) {
		return
	}
	fail := func(code int, err error) {
		s.log(r, "oauth", req.Project, req.Name, "exchange", err)
		writeErr(w, code, err)
	}
	if req.Binding == nil || req.Binding.OAuth == nil {
		fail(http.StatusBadRequest, errors.New("an OAuth binding (--host, --token-url, --client-id) is required"))
		return
	}
	if req.Code == "" || req.RedirectURI == "" || req.CodeVerifier == "" {
		fail(http.StatusBadRequest, errors.New("code, redirect_uri and code_verifier are required"))
		return
	}
	// Check the binding and the name before the network call.
	sec := store.Secret{Project: req.Project, Name: req.Name, Tier: store.TierProxy, Binding: req.Binding, Value: "pending", Default: req.Default}
	if err := sec.Validate(); err != nil {
		fail(http.StatusBadRequest, err)
		return
	}
	if _, err := s.Store.Get(req.Project, req.Name); err == nil {
		fail(http.StatusConflict, fmt.Errorf("%s: %w", sec.Key(), store.ErrExists))
		return
	} else if !errors.Is(err, store.ErrNotFound) {
		fail(http.StatusInternalServerError, err)
		return
	}
	if s.State.IsLocked(req.Project) {
		fail(http.StatusForbidden, fmt.Errorf("project %s is locked", req.Project))
		return
	}
	o := req.Binding.OAuth
	clientID, clientSecret, err := s.Store.OAuthClient(req.Project, o)
	if err != nil {
		fail(http.StatusBadRequest, err)
		return
	}
	secretValue := ""
	if clientSecret != nil {
		if s.State.IsLocked(clientSecret.Project) {
			fail(http.StatusForbidden, fmt.Errorf("project %s is locked", clientSecret.Project))
			return
		}
		secretValue = clientSecret.Value
	}

	hc := s.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	tok, err := oauth.Exchange(r.Context(), hc, o.TokenURL, clientID, secretValue, req.Code, req.RedirectURI, req.CodeVerifier)
	if err != nil {
		fail(http.StatusBadGateway, fmt.Errorf("code exchange failed: %w", err))
		return
	}
	res := OAuthExchangeResult{Stored: sec.Key(), Scopes: tok.Scopes()}
	if res.Scopes == nil {
		res.Scopes = []string{}
	}

	// Checks. A token that fails one is revoked when the provider has a
	// revocation endpoint, and nothing is stored.
	reject := func(msg string) {
		if req.RevokeURL != "" {
			t := tok.Refresh
			if t == "" {
				t = tok.Access
			}
			if oauth.Revoke(r.Context(), hc, req.RevokeURL, t) == nil {
				msg += "; the token was revoked"
			} else {
				msg += "; the token could NOT be revoked: remove the app's access in the account settings"
			}
		}
		fail(http.StatusUnprocessableEntity, errors.New(msg+"; nothing was stored"))
	}
	if tok.Refresh == "" {
		reject("the provider sent no refresh token (for Google: access_type=offline and prompt=consent)")
		return
	}
	if len(req.Scopes) > 0 && tok.Scope != "" {
		granted := map[string]bool{}
		for _, sc := range tok.Scopes() {
			granted[sc] = true
		}
		var missing []string
		for _, sc := range req.Scopes {
			if !granted[sc] {
				missing = append(missing, sc)
			}
		}
		if len(missing) > 0 {
			reject("scopes not granted: " + strings.Join(missing, ", ") + " (tick every box on the consent page)")
			return
		}
	}
	if req.Account != "" {
		email, err := oauth.IDTokenEmail(tok.IDToken)
		if err != nil {
			reject("cannot check the account: " + err.Error())
			return
		}
		if email != strings.ToLower(req.Account) {
			reject(fmt.Sprintf("the consent came from %s, not %s", email, req.Account))
			return
		}
		res.Account = email
	}

	sec.Value = tok.Refresh
	if err := s.Store.Create(sec, s.now()); err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, store.ErrExists) {
			code = http.StatusConflict
		}
		fail(code, err)
		return
	}
	s.log(r, "oauth", req.Project, req.Name, "exchange stored "+o.TokenHost(), nil)
	writeJSON(w, res)
}
