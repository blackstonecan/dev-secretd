package api

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/blackstonecan/dev-secretd/internal/store"
)

func setKeyed(t *testing.T, c *Client) {
	t.Helper()
	must(t, c.Set(SetRequest{Project: "demo", Name: "MAIL", Tier: store.TierProxy, Value: "sk-mail",
		Binding: &store.Binding{Host: "api.example.com", Header: "x-api-key", RunKey: true}}))
	must(t, c.Set(SetRequest{Project: "demo", Name: "PLAIN", Tier: store.TierProxy, Value: "sk-plain",
		Binding: &store.Binding{Host: "api.example.com", Header: "x-api-key"}}))
}

func waitCount(t *testing.T, st func() int, want int) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if st() == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("run key count is %d, want %d", st(), want)
}

func TestResolveRunKey(t *testing.T) {
	c, _, dir, keys := startServerKeys(t, os.Getuid())
	setKeyed(t, c)
	items := []ResolveItem{{Name: "MAIL", Tier: store.TierProxy}, {Name: "PLAIN", Tier: store.TierProxy}}

	// The plain Resolve cannot get a keyed secret.
	_, err := c.Resolve(ResolveRequest{Project: "demo", Items: items})
	if err == nil || !strings.Contains(err.Error(), "needs a per-run key") {
		t.Fatalf("want a key refusal, got %v", err)
	}
	if keys.Count() != 0 {
		t.Fatal("a key was issued without a hold")
	}

	res, closer, err := c.ResolveHold(ResolveRequest{Project: "demo", Items: items})
	must(t, err)
	if len(res[0].Key) != 64 || !res[0].RunKey || res[0].BaseURL != "http://127.0.0.1:7777/demo/MAIL/rk-"+res[0].Key {
		t.Fatalf("keyed item: %+v", res[0])
	}
	if res[1].Key != "" || res[1].RunKey || res[1].BaseURL != "http://127.0.0.1:7777/demo/PLAIN" {
		t.Fatalf("plain item: %+v", res[1])
	}
	key := res[0].Key
	if keys.Count() != 1 || !keys.Valid(key, "demo", "MAIL") || keys.Valid(key, "demo", "PLAIN") {
		t.Fatal("key not live for MAIL only")
	}
	// Closing the connection ends the key.
	must(t, closer.Close())
	waitCount(t, keys.Count, 0)
	if keys.Valid(key, "demo", "MAIL") {
		t.Fatal("key lives after the close")
	}
	for i := 0; i < 50; i++ {
		raw, _ := os.ReadFile(dir + "/audit.log")
		if strings.Contains(string(raw), "revoked: run ended") {
			if strings.Contains(string(raw), key) {
				t.Fatal("audit log has the run key")
			}
			if !strings.Contains(string(raw), "run-key") {
				t.Fatal("resolve line does not say run-key")
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no run-key audit line")
}

func TestLockRevokesRunKeys(t *testing.T) {
	c, _, dir, keys := startServerKeys(t, os.Getuid())
	setKeyed(t, c)
	res, closer, err := c.ResolveHold(ResolveRequest{Project: "demo", Items: []ResolveItem{{Name: "MAIL", Tier: store.TierProxy}}})
	must(t, err)
	defer closer.Close()
	must(t, c.Lock("other", true))
	if !keys.Valid(res[0].Key, "demo", "MAIL") {
		t.Fatal("locking another project revoked the key")
	}
	must(t, c.Lock("demo", true))
	if keys.Valid(res[0].Key, "demo", "MAIL") {
		t.Fatal("key lives after the lock")
	}
	st, err := c.Status()
	must(t, err)
	if st.RunKeys != 0 {
		t.Fatalf("status run_keys %d", st.RunKeys)
	}
	raw, _ := os.ReadFile(dir + "/audit.log")
	if !strings.Contains(string(raw), "revoked 1 run key(s)") {
		t.Fatalf("lock audit line: %s", raw)
	}
}

func TestStatusCountsRunKeys(t *testing.T) {
	c, _, _, _ := startServerKeys(t, os.Getuid())
	setKeyed(t, c)
	_, closer, err := c.ResolveHold(ResolveRequest{Project: "demo", Items: []ResolveItem{{Name: "MAIL", Tier: store.TierProxy}}})
	must(t, err)
	st, err := c.Status()
	must(t, err)
	if st.RunKeys != 1 {
		t.Fatalf("run_keys %d", st.RunKeys)
	}
	closer.Close()
	waitCount(t, func() int { s, _ := c.Status(); return s.RunKeys }, 0)
}
