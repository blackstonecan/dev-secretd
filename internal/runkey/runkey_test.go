package runkey

import (
	"sync"
	"testing"
	"time"
)

func TestIssueAndValid(t *testing.T) {
	r := New()
	key, _, err := r.Issue([]string{"demo/MAIL", "demo/OTHER"})
	if err != nil || len(key) != 64 {
		t.Fatalf("issue: %v %q", err, key)
	}
	if !r.Valid(key, "demo", "MAIL") || !r.Valid(key, "demo", "OTHER") {
		t.Fatal("key not valid for its secrets")
	}
	if r.Valid(key, "demo", "NOPE") || r.Valid(key, "other", "MAIL") {
		t.Fatal("key valid for a secret it does not cover")
	}
	if r.Valid("", "demo", "MAIL") || r.Valid("x"+key, "demo", "MAIL") {
		t.Fatal("wrong key accepted")
	}
	var nilReg *Registry
	if nilReg.Valid(key, "demo", "MAIL") {
		t.Fatal("nil registry accepted a key")
	}
	k2, _, _ := r.Issue([]string{"demo/MAIL"})
	if k2 == key {
		t.Fatal("two runs got the same key")
	}
	if r.Count() != 2 {
		t.Fatalf("count %d", r.Count())
	}
}

func TestRevoke(t *testing.T) {
	r := New()
	key, run, _ := r.Issue([]string{"demo/MAIL"})
	r.Revoke(run)
	r.Revoke(run) // twice is fine
	if r.Valid(key, "demo", "MAIL") || r.Count() != 0 {
		t.Fatal("key still live")
	}
	select {
	case <-run.Done():
	default:
		t.Fatal("Done not closed")
	}
}

func TestRevokeProject(t *testing.T) {
	r := New()
	a, runA, _ := r.Issue([]string{"demo/MAIL"})
	b, _, _ := r.Issue([]string{"other/MAIL"})
	c, _, _ := r.Issue([]string{"other/X", "demo/Y"})
	if n := r.RevokeProject("demo"); n != 2 {
		t.Fatalf("revoked %d", n)
	}
	if r.Valid(a, "demo", "MAIL") || r.Valid(c, "demo", "Y") || !r.Valid(b, "other", "MAIL") {
		t.Fatal("wrong runs revoked")
	}
	select {
	case <-runA.Done():
	default:
		t.Fatal("Done not closed")
	}
	if n := r.RevokeProject("demo"); n != 0 {
		t.Fatalf("second revoke: %d", n)
	}
}

func TestRevokeAll(t *testing.T) {
	r := New()
	_, run1, _ := r.Issue([]string{"a/X"})
	_, run2, _ := r.Issue([]string{"b/X"})
	r.RevokeAll()
	if r.Count() != 0 {
		t.Fatal("runs left")
	}
	for _, run := range []*Run{run1, run2} {
		select {
		case <-run.Done():
		case <-time.After(time.Second):
			t.Fatal("Done not closed")
		}
	}
}

func TestConcurrent(t *testing.T) {
	r := New()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key, run, _ := r.Issue([]string{"demo/MAIL"})
			r.Valid(key, "demo", "MAIL")
			r.RevokeProject("other")
			r.Count()
			r.Revoke(run)
		}()
	}
	wg.Add(1)
	go func() { defer wg.Done(); r.RevokeAll() }()
	wg.Wait()
}
