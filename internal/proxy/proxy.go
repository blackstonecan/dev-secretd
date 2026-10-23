// Package proxy adds proxy-tier secrets to outgoing requests.
//
// A client calls http://127.0.0.1:<port>/<project>/<NAME>/<path> with a
// placeholder credential. The proxy removes the client's credential, adds the
// real secret, and forwards the request over HTTPS to the bound host only.
// Secret values are masked in response headers and bodies.
package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/blackstonecan/dev-secretd/internal/redact"
	"github.com/blackstonecan/dev-secretd/internal/state"
	"github.com/blackstonecan/dev-secretd/internal/store"
)

type Proxy struct {
	Store     *store.Store
	State     *state.State
	Audit     *state.Audit
	Transport http.RoundTripper // nil = http.DefaultTransport
	// Scheme of the upstream. Always "https" outside tests.
	Scheme string
}

// BaseURL is the URL that a client of project/name uses.
func BaseURL(addr, project, name string) string {
	return "http://" + addr + "/" + project + "/" + name
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	project, name, rest, ok := splitPath(r.URL.EscapedPath())
	if !ok {
		http.Error(w, "secretd: path must be /<project>/<NAME>/...", http.StatusBadRequest)
		return
	}
	ev := state.Event{Op: "proxy", Project: project, Name: name}
	fail := func(code int, msg string) {
		ev.Error = msg
		p.Audit.Log(ev)
		http.Error(w, "secretd: "+msg, code)
	}

	if p.State.IsLocked(project) {
		fail(http.StatusForbidden, "project "+project+" is locked")
		return
	}
	sec, err := p.Store.Get(project, name)
	if errors.Is(err, store.ErrNotFound) {
		fail(http.StatusNotFound, "no secret "+project+"/"+name)
		return
	}
	if err != nil {
		fail(http.StatusInternalServerError, "store error")
		return
	}
	if sec.Tier != store.TierProxy || sec.Binding == nil {
		fail(http.StatusForbidden, project+"/"+name+" is not a proxy-tier secret")
		return
	}

	b := sec.Binding
	// Basic auth takes its username from a public value: the secret's
	// project first, then the user scope.
	username := ""
	if b.Basic != "" {
		u, err := p.Store.ResolvePublic(sec.Project, b.Basic)
		if err != nil {
			fail(http.StatusInternalServerError, fmt.Sprintf("basic username %s: %v (set it with `secret set %s NAME --public`)", b.Basic, err, b.Basic))
			return
		}
		username = u.Value
	}
	host, rest := pickHost(b, rest)
	scheme := p.Scheme
	if scheme == "" {
		scheme = "https"
	}
	target := &url.URL{Scheme: scheme, Host: host}
	status := 0
	// The header value can hold the secret in another form (Basic auth is
	// base64); mask that too.
	masks := []string{sec.Value}
	headerValue := ""
	if b.Header != "" {
		headerValue = b.HeaderValue(sec.Value, username)
		if !strings.Contains(headerValue, sec.Value) {
			masks = append(masks, strings.TrimPrefix(headerValue, "Basic "))
		}
	}

	rp := &httputil.ReverseProxy{
		Transport: p.Transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = target.Scheme
			pr.Out.URL.Host = target.Host
			pr.Out.URL.Path, pr.Out.URL.RawPath = rest, ""
			if u, err := url.PathUnescape(rest); err == nil {
				pr.Out.URL.Path, pr.Out.URL.RawPath = u, rest
			}
			pr.Out.Host = target.Host
			// The client's Accept-Encoding would make the upstream send compressed
			// bytes, which the masking cannot read. Without it, the transport asks
			// for gzip itself and decompresses before ModifyResponse.
			pr.Out.Header.Del("Accept-Encoding")
			// Never forward the client's own credentials to the upstream.
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Del("Proxy-Authorization")
			if b.Header != "" {
				pr.Out.Header.Del(b.Header)
				pr.Out.Header.Set(b.Header, headerValue)
			} else {
				q := pr.Out.URL.Query()
				q.Set(b.Query, sec.Value)
				pr.Out.URL.RawQuery = q.Encode()
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			status = resp.StatusCode
			for k, vs := range resp.Header {
				for i, v := range vs {
					resp.Header[k][i] = redact.String(v, masks...)
				}
			}
			resp.Body = &redactBody{rc: resp.Body, values: masks}
			resp.Header.Del("Content-Length")
			resp.ContentLength = -1
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			ev.Error = redact.String(err.Error(), masks...)
			http.Error(w, "secretd: upstream error", http.StatusBadGateway)
		},
		// Stream responses (SSE) at once.
		FlushInterval: -1,
	}
	rp.ServeHTTP(w, r)

	// The path only: a query parameter can hold the secret.
	ev.Detail = fmt.Sprintf("%s %s %s %d", r.Method, host, redact.String(rest, masks...), status)
	p.Audit.Log(ev)
}

// pickHost returns the upstream host and the path to send there. When the
// first path segment is exactly one of the bound hosts, it picks that host
// and is removed; otherwise the default host gets the whole path. Host names
// have dots and must match a binding, so an API path is never taken for one,
// and a host that is not bound can never be reached.
func pickHost(b *store.Binding, rest string) (string, string) {
	seg, after, _ := strings.Cut(strings.TrimPrefix(rest, "/"), "/")
	for _, h := range b.ExtraHosts {
		if strings.EqualFold(seg, h) {
			return h, "/" + after
		}
	}
	if strings.EqualFold(seg, b.Host) && len(b.ExtraHosts) > 0 {
		return b.Host, "/" + after
	}
	return b.Host, rest
}

// splitPath turns "/proj/NAME/v1/x" into ("proj", "NAME", "/v1/x").
func splitPath(p string) (project, name, rest string, ok bool) {
	parts := strings.SplitN(strings.TrimPrefix(p, "/"), "/", 3)
	if len(parts) < 2 || !store.ValidProject(parts[0]) || !store.ValidName(parts[1]) {
		return "", "", "", false
	}
	rest = "/"
	if len(parts) == 3 {
		rest += parts[2]
	}
	return parts[0], parts[1], rest, true
}

// redactBody masks the value in the body. A value split across reads is
// still masked, because redact.Writer holds back a short tail (at most
// len(value)-1 bytes, so streamed events can arrive a little later).
type redactBody struct {
	rc     io.ReadCloser
	values []string
	out    bytes.Buffer
	w      *redact.Writer
	tmp    []byte
	eof    bool
}

func (r *redactBody) Read(p []byte) (int, error) {
	if r.w == nil {
		r.w = redact.NewWriter(&r.out, r.values...)
		r.tmp = make([]byte, 32*1024)
	}
	for r.out.Len() == 0 {
		if r.eof {
			return 0, io.EOF
		}
		n, err := r.rc.Read(r.tmp)
		if n > 0 {
			_, _ = r.w.Write(r.tmp[:n])
		}
		if err == io.EOF {
			r.eof = true
			_ = r.w.Flush()
		} else if err != nil {
			return 0, err
		}
	}
	return r.out.Read(p)
}

func (r *redactBody) Close() error { return r.rc.Close() }
