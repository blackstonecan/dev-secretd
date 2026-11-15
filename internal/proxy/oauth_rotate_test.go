package proxy

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// rotating makes the token endpoint of f behave like a provider with
// single-use refresh tokens: each answer carries the next refresh token, and
// a refresh token that was used before is refused. It returns the refresh
// tokens the endpoint saw.
func rotating(f *oauthFixture) *[]string {
	var seen []string
	valid := "rt-refresh-1"
	f.tokenReply = func(form map[string]string, n int) (int, string) {
		seen = append(seen, form["refresh_token"])
		if form["refresh_token"] != valid {
			return 400, `{"error":"invalid_grant"}`
		}
		valid = fmt.Sprintf("rt-refresh-%d", n+1)
		return 200, fmt.Sprintf(`{"access_token":"at-%d","refresh_token":%q,"expires_in":3600}`, n, valid)
	}
	return &seen
}

func (f *oauthFixture) stored(t *testing.T) string {
	t.Helper()
	sec, err := f.store.Get("mail", "GMAIL_REFRESH")
	must(t, err)
	return sec.Value
}

// A provider with single-use refresh tokens: the new one is stored, and the
// next refresh uses it.
func TestOAuthRotatingRefreshTokenIsStored(t *testing.T) {
	f := newOAuthFixture(t)
	seen := rotating(f)
	before, _ := f.store.Get("mail", "GMAIL_REFRESH")

	if resp, body := get(t, f.proxy.URL+"/mail/GMAIL_REFRESH/x", nil); resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if got := f.stored(t); got != "rt-refresh-2" {
		t.Fatalf("store has %q after the first refresh", got)
	}
	after, _ := f.store.Get("mail", "GMAIL_REFRESH")
	if !after.UpdatedAt.After(before.UpdatedAt) || after.Binding == nil || after.Binding.OAuth == nil {
		t.Fatalf("stored secret: %+v", after)
	}
	// The cached access token is still used: the save is not a rotation by root.
	get(t, f.proxy.URL+"/mail/GMAIL_REFRESH/x", nil)
	if f.refreshN.Load() != 1 {
		t.Fatalf("refreshes %d, want 1", f.refreshN.Load())
	}

	// A 401 forces the second refresh: it must use the stored, new token.
	f.apiReply = func(bearer string) (int, string) {
		if bearer == "at-1" {
			return 401, "expired"
		}
		return 200, "ok " + bearer
	}
	if resp, body := get(t, f.proxy.URL+"/mail/GMAIL_REFRESH/x", nil); resp.StatusCode != 200 {
		t.Fatalf("after 401: %d %s", resp.StatusCode, body)
	}
	if got := strings.Join(*seen, ","); got != "rt-refresh-1,rt-refresh-2" {
		t.Fatalf("token endpoint saw %s", got)
	}
	if got := f.stored(t); got != "rt-refresh-3" {
		t.Fatalf("store has %q after the second refresh", got)
	}

	log := f.audit(t)
	if strings.Contains(log, "rt-refresh") || strings.Contains(log, "at-1") {
		t.Fatalf("audit log has a token: %s", log)
	}
	if strings.Count(log, "rotated refresh token saved") != 2 {
		t.Fatalf("audit: %s", log)
	}
}

// A request that read the secret before a rotation was saved (first request:
// the 401 retry inside one request) keeps working.
func TestOAuthRotationInsideOneRequest(t *testing.T) {
	f := newOAuthFixture(t)
	seen := rotating(f)
	f.apiReply = func(bearer string) (int, string) {
		if bearer == "at-1" {
			return 401, "no"
		}
		return 200, "ok"
	}
	resp, body := get(t, f.proxy.URL+"/mail/GMAIL_REFRESH/x", nil)
	if resp.StatusCode != 200 || body != "ok" {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if got := strings.Join(*seen, ","); got != "rt-refresh-1,rt-refresh-2" {
		t.Fatalf("token endpoint saw %s", got)
	}
	if got := f.stored(t); got != "rt-refresh-3" {
		t.Fatalf("store has %q", got)
	}
}

// A value that root rotates wins over the token the proxy holds.
func TestOAuthRootRotateWinsOverRotation(t *testing.T) {
	f := newOAuthFixture(t)
	rotating(f)
	get(t, f.proxy.URL+"/mail/GMAIL_REFRESH/x", nil)
	must(t, f.store.Rotate("mail", "GMAIL_REFRESH", "rt-from-root", time.Now()))
	var form map[string]string
	f.tokenReply = func(fm map[string]string, n int) (int, string) {
		form = fm
		return 200, `{"access_token":"at-root","expires_in":3600}`
	}
	get(t, f.proxy.URL+"/mail/GMAIL_REFRESH/x", nil)
	if form["refresh_token"] != "rt-from-root" || f.apiAuth[len(f.apiAuth)-1] != "Bearer at-root" {
		t.Fatalf("form %v auth %v", form, f.apiAuth)
	}
	if got := f.stored(t); got != "rt-from-root" {
		t.Fatalf("store has %q", got)
	}
}

// A provider that sends the same refresh token again, or none, changes nothing.
func TestOAuthNoRotationNoWrite(t *testing.T) {
	f := newOAuthFixture(t)
	before, _ := f.store.Get("mail", "GMAIL_REFRESH")
	f.tokenReply = func(_ map[string]string, n int) (int, string) {
		return 200, `{"access_token":"at-1","refresh_token":"rt-refresh-1","expires_in":3600}`
	}
	get(t, f.proxy.URL+"/mail/GMAIL_REFRESH/x", nil)
	after, _ := f.store.Get("mail", "GMAIL_REFRESH")
	if after.Value != "rt-refresh-1" || !after.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatalf("secret was written: %+v", after)
	}
	if strings.Contains(f.audit(t), "rotated") {
		t.Fatalf("audit: %s", f.audit(t))
	}
}

// When the store cannot take the new refresh token, the proxy keeps working
// with the token in memory and saves it on a later request.
func TestOAuthRotationSaveFailsThenRecovers(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write to a read-only directory")
	}
	f := newOAuthFixture(t)
	seen := rotating(f)
	old := saveRetry
	saveRetry = time.Hour
	t.Cleanup(func() { saveRetry = old })

	// A first line, so the audit file exists before the directory is closed.
	get(t, f.proxy.URL+"/mail/NO_SUCH/x", nil)
	must(t, os.Chmod(f.dir, 0o500))
	t.Cleanup(func() { os.Chmod(f.dir, 0o700) })

	if resp, body := get(t, f.proxy.URL+"/mail/GMAIL_REFRESH/x", nil); resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if got := f.stored(t); got != "rt-refresh-1" {
		t.Fatalf("store has %q, the write should have failed", got)
	}
	if !strings.Contains(f.audit(t), "NOT saved") {
		t.Fatalf("audit: %s", f.audit(t))
	}

	// The next refresh uses the token in memory, not the dead one in the store.
	f.apiReply = func(bearer string) (int, string) {
		if bearer == "at-1" {
			return 401, "expired"
		}
		return 200, "ok"
	}
	if resp, body := get(t, f.proxy.URL+"/mail/GMAIL_REFRESH/x", nil); resp.StatusCode != 200 {
		t.Fatalf("second refresh: %d %s", resp.StatusCode, body)
	}
	if got := strings.Join(*seen, ","); got != "rt-refresh-1,rt-refresh-2" {
		t.Fatalf("token endpoint saw %s", got)
	}

	// The directory is writable again: a request without a refresh saves it.
	must(t, os.Chmod(f.dir, 0o700))
	saveRetry = 0
	get(t, f.proxy.URL+"/mail/GMAIL_REFRESH/x", nil)
	if f.refreshN.Load() != 2 {
		t.Fatalf("refreshes %d, want 2", f.refreshN.Load())
	}
	if got := f.stored(t); got != "rt-refresh-3" {
		t.Fatalf("store has %q after the retry", got)
	}
}

// A rotated refresh token is masked in a response, like the access tokens.
func TestOAuthRotatedRefreshTokenIsMasked(t *testing.T) {
	f := newOAuthFixture(t)
	rotating(f)
	f.apiReply = func(string) (int, string) { return 200, "leak rt-refresh-2 end" }
	if _, body := get(t, f.proxy.URL+"/mail/GMAIL_REFRESH/x", nil); body != "leak *** end" {
		t.Fatalf("body %q", body)
	}
}
