// Package api is the Unix-socket API between the `secret` CLI and secretd.
//
// The API is write-only for secret values, with one exception: run-tier
// values go to `secret run`, which puts them into a child process. Proxy-tier
// values never leave the daemon. Public values are not secret: list, get and
// resolve return them, and set may change them. Changes to existing secrets (rotate, rm,
// bind) are not in this API; only root can make them, on the store directly.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/blackstonecan/dev-secretd/internal/proxy"
	"github.com/blackstonecan/dev-secretd/internal/runkey"
	"github.com/blackstonecan/dev-secretd/internal/state"
	"github.com/blackstonecan/dev-secretd/internal/store"
)

type SetRequest struct {
	Project string         `json:"project"`
	Name    string         `json:"name"`
	Tier    store.Tier     `json:"tier"`
	Kind    store.Kind     `json:"kind,omitempty"`
	Binding *store.Binding `json:"binding,omitempty"`
	Value   string         `json:"value"`
	Default bool           `json:"default,omitempty"` // user scope only
}

// Info describes a secret without its value.
type Info struct {
	Project   string         `json:"project"`
	Name      string         `json:"name"`
	Tier      store.Tier     `json:"tier"`
	Kind      store.Kind     `json:"kind,omitempty"`
	Binding   *store.Binding `json:"binding,omitempty"`
	Default   bool           `json:"default,omitempty"`
	Value     string         `json:"value,omitempty"` // public values only
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	Locked    bool           `json:"locked"`
}

type ResolveRequest struct {
	Project string        `json:"project"`
	Items   []ResolveItem `json:"items"`
	// Hold: the caller keeps the connection open for the life of the run; keys
	// for run_key secrets die when it closes.
	Hold bool `json:"hold,omitempty"`
}

type ResolveItem struct {
	Name string     `json:"name"`
	Tier store.Tier `json:"tier"` // what the manifest expects; must match the store
	// When the project has no NAME: "user" uses user/NAME, "" uses user/NAME
	// only if it is a default, "none" never falls back.
	Fallback string `json:"fallback,omitempty"`
}

type Resolved struct {
	Project string     `json:"project"` // where the secret came from: the project or "user"
	Name    string     `json:"name"`
	Tier    store.Tier `json:"tier"`
	Kind    store.Kind `json:"kind,omitempty"`
	BaseURL string     `json:"base_url,omitempty"` // proxy tier
	Value   string     `json:"value,omitempty"`    // run tier
	// RunKey: the proxy needs this run's key for the item. BaseURL carries it.
	// Key is the same for all keyed items of one run.
	RunKey bool   `json:"run_key,omitempty"`
	Key    string `json:"key,omitempty"`
}

type ProjectRequest struct {
	Project string `json:"project"`
}

// OAuthExchangeRequest asks the daemon to finish an OAuth consent: it
// exchanges the authorization code at the binding's token endpoint and stores
// the refresh token as a new proxy-tier secret. No token reaches the caller.
type OAuthExchangeRequest struct {
	Project string `json:"project"`
	Name    string `json:"name"`
	// Binding of the new secret: the API hosts and the OAuth part (token
	// URL, client id and client secret by name).
	Binding      *store.Binding `json:"binding"`
	Code         string         `json:"code"`
	RedirectURI  string         `json:"redirect_uri"`
	CodeVerifier string         `json:"code_verifier"`
	// Scopes that must all be granted, else nothing is stored.
	Scopes []string `json:"scopes,omitempty"`
	// Account (optional): the email the id_token must name, else nothing is
	// stored. Needs the openid and email scopes.
	Account string `json:"account,omitempty"`
	// RevokeURL (optional): tokens that fail a check are revoked here.
	RevokeURL string `json:"revoke_url,omitempty"`
	Default   bool   `json:"default,omitempty"` // user scope only
}

type OAuthExchangeResult struct {
	Stored  string   `json:"stored"`
	Scopes  []string `json:"scopes"`            // granted scopes, when the provider says
	Account string   `json:"account,omitempty"` // the id_token's email, when there is one
	Revoked bool     `json:"revoked,omitempty"`
}

type Status struct {
	ProxyAddr string   `json:"proxy_addr"`
	Locked    []string `json:"locked"`
	Secrets   int      `json:"secrets"`
	RunKeys   int      `json:"run_keys"` // live runs that hold a run key
}

type errorBody struct {
	Error string `json:"error"`
}

// Server serves the API. AllowUID is the one non-root user that may call it.
type Server struct {
	Store     *store.Store
	State     *state.State
	Audit     *state.Audit
	AllowUID  int
	ProxyAddr string
	Now       func() time.Time
	// HTTP reaches OAuth token endpoints. nil = a default client.
	HTTP *http.Client
	// Keys holds the per-run keys. Share it with the proxy.
	Keys *runkey.Registry
}

type callerKey struct{}

type caller struct{ uid, pid int }

func (c caller) String() string { return fmt.Sprintf("uid=%d pid=%d", c.uid, c.pid) }

// ConnContext stores the peer credentials of each connection. Use it as
// http.Server.ConnContext.
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return ctx
	}
	uid, pid, err := peerCred(uc)
	if err != nil {
		return ctx
	}
	return context.WithValue(ctx, callerKey{}, caller{uid, pid})
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/set", s.set)
	mux.HandleFunc("GET /v1/list", s.list)
	mux.HandleFunc("GET /v1/get", s.get)
	mux.HandleFunc("POST /v1/resolve", s.resolve)
	mux.HandleFunc("POST /v1/oauth/exchange", s.oauthExchange)
	mux.HandleFunc("POST /v1/lock", s.lockFn(true))
	mux.HandleFunc("POST /v1/unlock", s.lockFn(false))
	mux.HandleFunc("GET /v1/status", s.status)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := r.Context().Value(callerKey{}).(caller)
		if !ok || (c.uid != s.AllowUID && c.uid != 0) {
			writeErr(w, http.StatusForbidden, errors.New("caller is not allowed"))
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) set(w http.ResponseWriter, r *http.Request) {
	var req SetRequest
	if !readJSON(w, r, &req) {
		return
	}
	if req.Tier == store.TierRun && req.Kind == "" {
		req.Kind = store.KindEnv
	}
	sec := store.Secret{Project: req.Project, Name: req.Name, Tier: req.Tier, Kind: req.Kind, Binding: req.Binding, Value: req.Value, Default: req.Default}
	var err error
	if req.Tier == store.TierPublic {
		// Public values are not secret, so the user may change them.
		if req.Kind != "" || req.Binding != nil || req.Default {
			err = errors.New("a public value has no kind, binding or default")
		} else {
			err = s.Store.SetPublic(req.Project, req.Name, req.Value, s.now())
		}
	} else {
		err = s.Store.Create(sec, s.now())
	}
	s.log(r, "set", req.Project, req.Name, string(req.Tier), err)
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, store.ErrExists) {
			code = http.StatusConflict
		}
		writeErr(w, code, err)
		return
	}
	writeJSON(w, map[string]string{"stored": sec.Key()})
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	secs, err := s.Store.List(r.URL.Query().Get("project"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]Info, 0, len(secs))
	for _, sec := range secs {
		out = append(out, info(&sec, s.State.IsLocked(sec.Project)))
	}
	writeJSON(w, out)
}

// info describes a secret. Only public values carry their value.
func info(sec *store.Secret, locked bool) Info {
	in := Info{
		Project: sec.Project, Name: sec.Name, Tier: sec.Tier, Kind: sec.Kind, Binding: sec.Binding, Default: sec.Default,
		CreatedAt: sec.CreatedAt, UpdatedAt: sec.UpdatedAt, Locked: locked,
	}
	if sec.Tier == store.TierPublic {
		in.Value = sec.Value
	}
	return in
}

// get returns a public value: the project's, or the user scope's.
func (s *Server) get(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	project, name := q.Get("project"), q.Get("name")
	if !store.ValidProject(project) || !store.ValidName(name) {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid project %q or name %q", project, name))
		return
	}
	sec, err := s.Store.ResolvePublic(project, name)
	switch {
	case errors.Is(err, store.ErrNotFound):
		where := project + "/" + name
		if project != store.UserProject {
			where += " or " + store.UserProject + "/" + name
		}
		writeErr(w, http.StatusNotFound, fmt.Errorf("no public value %s (add one with `secret set %s VALUE --public`)", where, name))
	case err != nil:
		writeErr(w, http.StatusForbidden, err)
	default:
		writeJSON(w, info(sec, s.State.IsLocked(sec.Project)))
	}
}

func (s *Server) resolve(w http.ResponseWriter, r *http.Request) {
	var req ResolveRequest
	if !readJSON(w, r, &req) {
		return
	}
	fail := func(code int, err error) {
		s.log(r, "resolve", req.Project, "", "", err)
		writeErr(w, code, err)
	}
	if s.State.IsLocked(req.Project) {
		fail(http.StatusForbidden, fmt.Errorf("project %s is locked", req.Project))
		return
	}
	// Read the rest of the body, so the server notices when the caller hangs up.
	_, _ = io.Copy(io.Discard, r.Body)
	out := make([]Resolved, 0, len(req.Items))
	var keyed []int // indexes in out
	for _, it := range req.Items {
		valid := it.Fallback == "" || (req.Project != store.UserProject && (it.Fallback == store.UserProject || it.Fallback == "none"))
		if !valid {
			fail(http.StatusBadRequest, fmt.Errorf("%s: invalid fallback %q for project %s", it.Name, it.Fallback, req.Project))
			return
		}
		sec, err := s.Store.Get(req.Project, it.Name)
		// Only a missing project secret falls back. A project secret that exists
		// always wins, and its errors (a tier mismatch) are never skipped.
		if errors.Is(err, store.ErrNotFound) && req.Project != store.UserProject && it.Fallback != "none" {
			u, uerr := s.Store.Get(store.UserProject, it.Name)
			switch {
			// Public values are not secret: they always fall back, and a locked
			// user scope does not block them. A private user secret of the name
			// still fails the tier check below, without its value.
			case it.Tier == store.TierPublic:
				if !errors.Is(uerr, store.ErrNotFound) {
					sec, err = u, uerr
				}
			case uerr == nil && (it.Fallback == store.UserProject || u.Default):
				if s.State.IsLocked(store.UserProject) {
					fail(http.StatusForbidden, fmt.Errorf("%s: project %s is locked", it.Name, store.UserProject))
					return
				}
				sec, err = u, nil
			case errors.Is(uerr, store.ErrNotFound) && it.Fallback == store.UserProject:
				fail(http.StatusNotFound, fmt.Errorf("no secret %s/%s or %s/%s (add one with `secret set`)",
					req.Project, it.Name, store.UserProject, it.Name))
				return
			case uerr != nil && !errors.Is(uerr, store.ErrNotFound):
				err = uerr
			}
		}
		if errors.Is(err, store.ErrNotFound) {
			fail(http.StatusNotFound, fmt.Errorf("no secret %s/%s (add it with `secret set`)", req.Project, it.Name))
			return
		}
		if err != nil {
			fail(http.StatusInternalServerError, err)
			return
		}
		// The store decides the tier. A manifest cannot turn a proxy secret into a run secret.
		if sec.Tier != it.Tier {
			fail(http.StatusConflict, fmt.Errorf("%s: the manifest says tier %s, the store says %s", sec.Key(), it.Tier, sec.Tier))
			return
		}
		res := Resolved{Project: sec.Project, Name: sec.Name, Tier: sec.Tier, Kind: sec.Kind}
		if sec.Tier == store.TierProxy {
			res.BaseURL = proxy.BaseURL(s.ProxyAddr, sec.Project, sec.Name)
			if sec.Binding != nil && sec.Binding.RunKey {
				res.RunKey = true
				keyed = append(keyed, len(out))
			}
		} else {
			res.Value = sec.Value
		}
		out = append(out, res)
	}
	var run *runkey.Run
	if len(keyed) > 0 {
		var ke *keyError
		if run, ke = s.issueKey(out, keyed, req); ke != nil {
			fail(ke.code, ke)
			return
		}
	}
	for _, it := range out {
		detail := string(it.Tier)
		if it.Project != req.Project {
			detail += " from " + it.Project
		}
		if it.RunKey {
			detail += " run-key"
		}
		s.log(r, "resolve", req.Project, it.Name, detail, nil)
	}
	writeJSON(w, out)
	if run == nil {
		return
	}
	// Hold the connection: the keys live as long as the caller does.
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	detail := "revoked: run ended"
	select {
	case <-r.Context().Done():
	case <-run.Done():
		detail = "revoked: locked or daemon stopping"
	}
	s.Keys.Revoke(run)
	s.log(r, "run-key", req.Project, "", detail, nil)
}

type keyError struct {
	code int
	msg  string
}

func (e *keyError) Error() string { return e.msg }

// issueKey makes the run key for the keyed items and puts it into them. The
// caller must hold the connection (req.Hold); else the key would never die.
func (s *Server) issueKey(out []Resolved, keyed []int, req ResolveRequest) (*runkey.Run, *keyError) {
	if !req.Hold {
		it := out[keyed[0]]
		return nil, &keyError{http.StatusBadRequest, fmt.Sprintf("%s/%s needs a per-run key: use `secret run` (update the secret CLI)", it.Project, it.Name)}
	}
	if s.Keys == nil {
		return nil, &keyError{http.StatusInternalServerError, "run keys are not enabled"}
	}
	// "<project>/" has no name: it only lets a lock of the run's own project end the run.
	names := []string{req.Project + "/"}
	for _, i := range keyed {
		names = append(names, out[i].Project+"/"+out[i].Name)
	}
	key, run, err := s.Keys.Issue(names)
	if err != nil {
		return nil, &keyError{http.StatusInternalServerError, "cannot make a run key"}
	}
	for _, i := range keyed {
		out[i].BaseURL += "/" + proxy.RunKeySegment(key)
		out[i].Key = key
	}
	return run, nil
}

func (s *Server) lockFn(locked bool) http.HandlerFunc {
	op := map[bool]string{true: "lock", false: "unlock"}[locked]
	return func(w http.ResponseWriter, r *http.Request) {
		var req ProjectRequest
		if !readJSON(w, r, &req) {
			return
		}
		if !store.ValidProject(req.Project) {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid project %q", req.Project))
			return
		}
		err := s.State.SetLocked(req.Project, locked, s.now())
		detail := ""
		if locked && err == nil {
			if n := s.Keys.RevokeProject(req.Project); n > 0 {
				detail = fmt.Sprintf("revoked %d run key(s)", n)
			}
		}
		s.log(r, op, req.Project, "", detail, err)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, map[string]string{op: req.Project})
	}
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	secs, err := s.Store.List("")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	st := Status{ProxyAddr: s.ProxyAddr, Locked: []string{}, Secrets: len(secs), RunKeys: s.Keys.Count()}
	seen := map[string]bool{}
	for _, sec := range secs {
		if !seen[sec.Project] && s.State.IsLocked(sec.Project) {
			st.Locked = append(st.Locked, sec.Project)
		}
		seen[sec.Project] = true
	}
	writeJSON(w, st)
}

func (s *Server) log(r *http.Request, op, project, name, detail string, err error) {
	ev := state.Event{Op: op, Project: project, Name: name, Detail: detail}
	if c, ok := r.Context().Value(callerKey{}).(caller); ok {
		ev.Caller = c.String()
	}
	if err != nil {
		ev.Error = err.Error()
	}
	s.Audit.Log(ev)
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("bad request: %w", err))
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(errorBody{Error: err.Error()})
}
