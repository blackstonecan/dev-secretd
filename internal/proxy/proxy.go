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

	"github.com/blackstonecan/secretd/internal/redact"
	"github.com/blackstonecan/secretd/internal/state"
	"github.com/blackstonecan/secretd/internal/store"
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
	scheme := p.Scheme
	if scheme == "" {
		scheme = "https"
	}
	target := &url.URL{Scheme: scheme, Host: b.Host}
	status := 0

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
				format := b.Format
				if format == "" {
					format = "{}"
				}
				pr.Out.Header.Set(b.Header, strings.Replace(format, "{}", sec.Value, 1))
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
					resp.Header[k][i] = redact.String(v, sec.Value)
				}
			}
			resp.Body = &redactBody{rc: resp.Body, value: sec.Value}
			resp.Header.Del("Content-Length")
			resp.ContentLength = -1
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			ev.Error = redact.String(err.Error(), sec.Value)
			http.Error(w, "secretd: upstream error", http.StatusBadGateway)
		},
		// Stream responses (SSE) at once.
		FlushInterval: -1,
	}
	rp.ServeHTTP(w, r)

	// The path only: a query parameter can hold the secret.
	ev.Detail = fmt.Sprintf("%s %s %s %d", r.Method, b.Host, redact.String(rest, sec.Value), status)
	p.Audit.Log(ev)
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
	rc    io.ReadCloser
	value string
	out   bytes.Buffer
	w     *redact.Writer
	tmp   []byte
	eof   bool
}

func (r *redactBody) Read(p []byte) (int, error) {
	if r.w == nil {
		r.w = redact.NewWriter(&r.out, r.value)
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
