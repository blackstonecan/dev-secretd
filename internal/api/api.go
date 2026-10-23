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
	"net"
	"net/http"
	"time"

	"github.com/blackstonecan/dev-secretd/internal/proxy"
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
}

type ProjectRequest struct {
	Project string `json:"project"`
}

type Status struct {
	ProxyAddr string   `json:"proxy_addr"`
	Locked    []string `json:"locked"`
	Secrets   int      `json:"secrets"`
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
	out := make([]Resolved, 0, len(req.Items))
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
		} else {
			res.Value = sec.Value
		}
		out = append(out, res)
	}
	for _, it := range out {
		detail := string(it.Tier)
		if it.Project != req.Project {
			detail += " from " + it.Project
		}
		s.log(r, "resolve", req.Project, it.Name, detail, nil)
	}
	writeJSON(w, out)
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
		s.log(r, op, req.Project, "", "", err)
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
	st := Status{ProxyAddr: s.ProxyAddr, Locked: []string{}, Secrets: len(secs)}
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
