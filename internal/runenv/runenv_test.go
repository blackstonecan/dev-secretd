package runenv

import (
	"os"
	"slices"
	"testing"

	"github.com/blackstonecan/secretd/internal/api"
	"github.com/blackstonecan/secretd/internal/manifest"
	"github.com/blackstonecan/secretd/internal/store"
)

func TestBuild(t *testing.T) {
	m := &manifest.Manifest{Project: "demo", Secrets: map[string]manifest.Entry{
		"API_KEY":     {Tier: store.TierProxy, Env: map[string]string{"BASE_URL": "{proxy}/v1", "API_KEY": "placeholder"}},
		"DB_PASSWORD": {Tier: store.TierRun},
		"SA_JSON":     {Tier: store.TierRun, Var: "GOOGLE_APPLICATION_CREDENTIALS"},
	}}
	resolved := []api.Resolved{
		{Name: "API_KEY", Tier: store.TierProxy, BaseURL: "http://127.0.0.1:7777/demo/API_KEY"},
		{Name: "DB_PASSWORD", Tier: store.TierRun, Kind: store.KindEnv, Value: "pw"},
		{Name: "SA_JSON", Tier: store.TierRun, Kind: store.KindFile, Value: `{"k":1}`},
	}
	env, err := Build(m, resolved, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer env.Cleanup()

	if env.Vars["BASE_URL"] != "http://127.0.0.1:7777/demo/API_KEY/v1" || env.Vars["API_KEY"] != "placeholder" {
		t.Fatalf("proxy vars: %v", env.Vars)
	}
	if env.Vars["DB_PASSWORD"] != "pw" {
		t.Fatalf("run var: %v", env.Vars)
	}
	p := env.Vars["GOOGLE_APPLICATION_CREDENTIALS"]
	raw, err := os.ReadFile(p)
	if err != nil || string(raw) != `{"k":1}` {
		t.Fatalf("file secret: %v %q", err, raw)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %v", st.Mode().Perm())
	}
	env.Cleanup()
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("file secret not removed")
	}
}

func TestMerge(t *testing.T) {
	got := Merge([]string{"A=1", "B=2"}, map[string]string{"B": "x", "C": "3"})
	slices.Sort(got)
	if !slices.Equal(got, []string{"A=1", "B=x", "C=3"}) {
		t.Fatalf("got %v", got)
	}
}
