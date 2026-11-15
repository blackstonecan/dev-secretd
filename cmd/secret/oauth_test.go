package main

import (
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestLoopbackRedirect(t *testing.T) {
	if addr, path, err := loopbackRedirect(""); err != nil || addr != "127.0.0.1:0" || path != "/" {
		t.Fatalf("default: %q %q %v", addr, path, err)
	}
	ok := map[string][2]string{
		"http://127.0.0.1:8765":                {"127.0.0.1:8765", "/"},
		"http://127.0.0.1:8765/":               {"127.0.0.1:8765", "/"},
		"http://127.0.0.1:8765/oauth/callback": {"127.0.0.1:8765", "/oauth/callback"},
	}
	for raw, want := range ok {
		addr, path, err := loopbackRedirect(raw)
		if err != nil || addr != want[0] || path != want[1] {
			t.Errorf("%s: got %q %q %v", raw, addr, path, err)
		}
	}
	for _, raw := range []string{
		"https://127.0.0.1:8765",         // not http
		"http://localhost:8765",          // may resolve to ::1
		"http://0.0.0.0:8765",            // not loopback only
		"http://example.com:8765",        // not this machine
		"http://127.0.0.1",               // no fixed port
		"http://127.0.0.1:0",             // no fixed port
		"http://127.0.0.1:99999",         // no such port
		"http://127.0.0.1:8765/cb?x=1",   // a query
		"http://127.0.0.1:8765/cb?",      // an empty query
		"http://127.0.0.1:8765/cb#frag",  // a fragment
		"http://user@127.0.0.1:8765/cb",  // user info
		"http://127.0.0.1.evil.com:8765", // another host
		"127.0.0.1:8765",                 // no scheme
	} {
		if _, _, err := loopbackRedirect(raw); err == nil {
			t.Errorf("%s: accepted", raw)
		}
	}
}

func TestAuthParamFlag(t *testing.T) {
	var p paramList
	if err := p.Set("resource=https://mcp.example.com/mcp?a=b"); err != nil {
		t.Fatal(err)
	}
	if len(p) != 1 || p[0][0] != "resource" || p[0][1] != "https://mcp.example.com/mcp?a=b" {
		t.Fatalf("%v", p)
	}
	for _, bad := range []string{"novalue", "=x"} {
		if err := p.Set(bad); err == nil {
			t.Errorf("%q: accepted", bad)
		}
	}
	for _, k := range []string{"client_id", "redirect_uri", "state", "code_challenge", "scope"} {
		if !reservedAuthParams[k] {
			t.Errorf("%s is not reserved", k)
		}
	}
}

// The callback is served on the path of the redirect URL only.
func TestWaitForCodePath(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	wait, err := waitForCode(ln, "st4te", "/oauth/callback")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + ln.Addr().String()
	resp, err := http.Get(base + "/?state=st4te&code=wrong-path")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("other path: %d", resp.StatusCode)
	}
	resp, err = http.Get(base + "/oauth/callback?state=st4te&code=the-code")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "Consent received") {
		t.Fatalf("page: %s", body)
	}
	code, err := wait()
	if err != nil || code != "the-code" {
		t.Fatalf("code %q %v", code, err)
	}
}
