package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/blackstonecan/dev-secretd/internal/api"
	"github.com/blackstonecan/dev-secretd/internal/manifest"
	"github.com/blackstonecan/dev-secretd/internal/store"
)

// Google's endpoints, for --google.
const (
	googleAuthURL   = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL  = "https://oauth2.googleapis.com/token"
	googleRevokeURL = "https://oauth2.googleapis.com/revoke"
)

const consentTimeout = 5 * time.Minute

func cmdOAuth(args []string) error {
	sub, rest := firstArg(args)
	if sub != "login" {
		return usageError{"usage: secret oauth login NAME [flags]"}
	}
	return cmdOAuthLogin(rest)
}

// cmdOAuthLogin runs an OAuth2 consent (loopback redirect + PKCE) and has
// the daemon exchange the code and store the refresh token as a proxy-tier
// secret. No token passes through this process.
func cmdOAuthLogin(args []string) error {
	fs := flag.NewFlagSet("oauth login", flag.ContinueOnError)
	project := fs.String("project", "", "")
	user := fs.Bool("user", false, "")
	def := fs.Bool("default", false, "")
	host := fs.String("host", "", "")
	authURL := fs.String("auth-url", "", "")
	tokenURL := fs.String("token-url", "", "")
	revokeURL := fs.String("revoke-url", "", "")
	google := fs.Bool("google", false, "")
	clientID := fs.String("client-id", "", "")
	clientSecret := fs.String("client-secret", "", "")
	scope := fs.String("scope", "", "")
	account := fs.String("account", "", "")
	noOpen := fs.Bool("no-open", false, "")
	runKey := fs.Bool("run-key", false, "")
	redirect := fs.String("redirect-uri", "", "")
	var authParams paramList
	fs.Var(&authParams, "auth-param", "")
	name, rest := firstArg(args)
	if err := fs.Parse(rest); err != nil {
		return usageError{err.Error()}
	}
	if name == "" || fs.NArg() > 0 {
		return usageError{"usage: secret oauth login NAME --host H[,H2] --client-id PUB --client-secret NAME --scope S[,S] (--google | --auth-url U --token-url U [--revoke-url U]) [--redirect-uri http://127.0.0.1:PORT[/PATH]] [--auth-param K=V]... [--account EMAIL] [--run-key] [--no-open]"}
	}
	listenAddr, callbackPath, err := loopbackRedirect(*redirect)
	if err != nil {
		return usageError{err.Error()}
	}
	for _, kv := range authParams {
		if reservedAuthParams[kv[0]] {
			return usageError{"--auth-param " + kv[0] + ": the command sets this parameter itself"}
		}
	}
	if *google {
		if *authURL == "" {
			*authURL = googleAuthURL
		}
		if *tokenURL == "" {
			*tokenURL = googleTokenURL
		}
		if *revokeURL == "" {
			*revokeURL = googleRevokeURL
		}
	}
	if *host == "" || *authURL == "" || *tokenURL == "" || *clientID == "" {
		return usageError{"--host, --client-id and the endpoints (--google, or --auth-url and --token-url) are required"}
	}
	if *user {
		if *project != "" {
			return usageError{"use --project or --user, not both"}
		}
		*project = store.UserProject
	}
	if *def && *project != store.UserProject {
		return usageError{"--default is for user-scope secrets: add --user"}
	}
	p, _, err := projectFor(*project)
	if err != nil {
		return err
	}
	scopes := manifest.SplitList(strings.ReplaceAll(*scope, " ", ","))
	if len(scopes) == 0 {
		return usageError{"--scope is required (comma-separated)"}
	}
	b := binding(*host, "", "", false, "", "", *tokenURL, *clientID, *clientSecret, *runKey)
	if err := (&store.Secret{Project: p, Name: name, Tier: store.TierProxy, Binding: b, Value: "pending", Default: *def}).Validate(); err != nil {
		return err
	}

	c, err := client()
	if err != nil {
		return err
	}
	// Stop before the consent if the name exists: `secret set` only adds.
	list, err := c.List(p)
	if err != nil {
		return err
	}
	for _, s := range list {
		if s.Name == name {
			return fmt.Errorf("%s/%s exists already: to replace it, run /usr/bin/sudo secret rm %s/%s in your own terminal, then this command again", p, name, p, name)
		}
	}
	id, err := c.Get(p, *clientID)
	if err != nil {
		return fmt.Errorf("client id %s: %w", *clientID, err)
	}

	// The account check reads the email claim of the id_token.
	consentScopes := append([]string{}, scopes...)
	if *account != "" {
		for _, s := range []string{"openid", "email"} {
			if !contains(consentScopes, s) {
				consentScopes = append(consentScopes, s)
			}
		}
	}

	verifier := randomURL(48)
	sum := sha256.Sum256([]byte(verifier))
	state := randomURL(24)
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		if *redirect != "" {
			return fmt.Errorf("cannot listen on %s for --redirect-uri: %w", listenAddr, err)
		}
		return err
	}
	// A provider that wants the redirect URL registered (Canva) compares it
	// byte for byte, so --redirect-uri is sent exactly as given.
	redirectURI := *redirect
	if redirectURI == "" {
		redirectURI = "http://" + ln.Addr().String()
	}

	q := url.Values{}
	for _, kv := range authParams {
		q.Set(kv[0], kv[1])
	}
	for k, v := range map[string]string{
		"client_id": id.Value, "redirect_uri": redirectURI, "response_type": "code",
		"scope": strings.Join(consentScopes, " "), "state": state,
		"code_challenge": base64.RawURLEncoding.EncodeToString(sum[:]), "code_challenge_method": "S256",
	} {
		q.Set(k, v)
	}
	if *google {
		// Without these Google gives no refresh token.
		q.Set("access_type", "offline")
		q.Set("prompt", "consent")
	}
	if *account != "" {
		q.Set("login_hint", *account)
	}
	u, err := url.Parse(*authURL)
	if err != nil {
		return fmt.Errorf("--auth-url: %w", err)
	}
	u.RawQuery = q.Encode()

	code, err := waitForCode(ln, state, callbackPath)
	defer ln.Close()
	open := func() {
		who := ""
		if *account != "" {
			who = " as " + *account
		}
		fmt.Fprintf(os.Stderr, "Sign in%s and give consent on this page:\n\n  %s\n\n", who, u.String())
		if !*noOpen {
			cmd := exec.Command("xdg-open", u.String())
			if err := cmd.Start(); err != nil {
				fmt.Fprintln(os.Stderr, "(Could not open a browser. Open the link above by hand.)")
			} else {
				go cmd.Wait()
			}
		}
		fmt.Fprintf(os.Stderr, "Waiting for the consent (%s)...\n", consentTimeout)
	}
	open()
	got, err := code()
	if err != nil {
		return err
	}

	res, err := c.OAuthExchange(api.OAuthExchangeRequest{
		Project: p, Name: name, Binding: b, Code: got, RedirectURI: redirectURI, CodeVerifier: verifier,
		Scopes: scopes, Account: *account, RevokeURL: *revokeURL, Default: *def,
	})
	if err != nil {
		return err
	}
	fmt.Printf("stored %s (tier proxy, OAuth refresh token)\n", res.Stored)
	if res.Account != "" {
		fmt.Printf("account: %s\n", res.Account)
	}
	if len(res.Scopes) > 0 {
		fmt.Printf("scopes: %s\n", strings.Join(res.Scopes, " "))
	}
	fmt.Printf("add to secrets.yaml:\n  %s:\n    tier: proxy\n    env:\n      SOME_API_BASE_URL: \"{proxy}\"   # secretd adds Authorization: Bearer <access token>\n", name)
	return nil
}

// reservedAuthParams are the consent parameters the command sets itself. An
// --auth-param can add to the consent URL (for example resource=...), never
// change these.
var reservedAuthParams = map[string]bool{
	"client_id": true, "redirect_uri": true, "response_type": true, "scope": true, "state": true,
	"code_challenge": true, "code_challenge_method": true,
}

// paramList collects repeated --auth-param K=V flags.
type paramList [][2]string

func (p *paramList) String() string { return "" }

func (p *paramList) Set(s string) error {
	k, v, ok := strings.Cut(s, "=")
	if !ok || k == "" {
		return errors.New("want KEY=VALUE")
	}
	*p = append(*p, [2]string{k, v})
	return nil
}

// loopbackRedirect returns the address to listen on and the callback path for
// --redirect-uri. Without one, the port is free to choose and the path is "/"
// (Google accepts any loopback port). A given URL must be a loopback URL on
// 127.0.0.1 with a fixed port: nothing else can receive the code safely.
func loopbackRedirect(raw string) (addr, path string, err error) {
	if raw == "" {
		return "127.0.0.1:0", "/", nil
	}
	bad := errors.New("--redirect-uri must be http://127.0.0.1:PORT or http://127.0.0.1:PORT/PATH")
	u, perr := url.Parse(raw)
	if perr != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.HasSuffix(raw, "?") || strings.HasSuffix(raw, "#") {
		return "", "", bad
	}
	port, perr := strconv.Atoi(u.Port())
	if perr != nil || port < 1 || port > 65535 {
		return "", "", bad
	}
	path = u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return net.JoinHostPort("127.0.0.1", u.Port()), path, nil
}

// waitForCode serves the loopback redirect on path. It returns a function
// that waits for exactly one callback with the right state.
func waitForCode(ln net.Listener, state, path string) (func() (string, error), error) {
	type result struct {
		code string
		err  error
	}
	done := make(chan result, 1)
	page := func(w http.ResponseWriter, text string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<!doctype html><meta charset=\"utf-8\"><title>secretd</title><p>%s</p>", text)
	}
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != path {
			http.NotFound(w, r)
			return
		}
		q := r.URL.Query()
		var res result
		switch {
		case q.Get("state") != state:
			page(w, "The state value does not match. Go back to the terminal.")
			res.err = errors.New("state mismatch: the callback is not from this consent")
		case q.Get("error") != "":
			page(w, "Consent was not given. Go back to the terminal.")
			res.err = errors.New("consent error: " + q.Get("error"))
		case q.Get("code") == "":
			page(w, "No code in the callback. Go back to the terminal.")
			res.err = errors.New("callback without a code")
		default:
			page(w, "Consent received. You can close this tab and go back to the terminal.")
			res.code = q.Get("code")
		}
		select {
		case done <- res:
		default:
		}
	})}
	go srv.Serve(ln)
	return func() (string, error) {
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			srv.Shutdown(ctx)
		}()
		select {
		case r := <-done:
			return r.code, r.err
		case <-time.After(consentTimeout):
			return "", errors.New("no answer from the consent page in " + consentTimeout.String())
		}
	}, nil
}

func randomURL(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
