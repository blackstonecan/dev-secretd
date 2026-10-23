// Package runenv builds the environment for `secret run`.
package runenv

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/blackstonecan/dev-secretd/internal/api"
	"github.com/blackstonecan/dev-secretd/internal/manifest"
	"github.com/blackstonecan/dev-secretd/internal/store"
)

// Env is the result: extra variables, and a directory with file secrets
// that the caller must remove when the child process ends.
type Env struct {
	Vars    map[string]string
	FileDir string
}

func (e *Env) Cleanup() {
	if e.FileDir != "" {
		_ = os.RemoveAll(e.FileDir)
	}
}

// Build maps resolved secrets to variables. runtimeDir should be in RAM
// ($XDG_RUNTIME_DIR); file secrets are written there with mode 0600.
func Build(m *manifest.Manifest, resolved []api.Resolved, runtimeDir string) (*Env, error) {
	env := &Env{Vars: map[string]string{}}
	for _, r := range resolved {
		e, ok := m.Secrets[r.Name]
		if !ok {
			return nil, fmt.Errorf("%s is not in the manifest", r.Name)
		}
		switch r.Tier {
		case store.TierProxy:
			for k, v := range e.Env {
				env.Vars[k] = strings.ReplaceAll(v, "{proxy}", r.BaseURL)
			}
		case store.TierPublic:
			name := e.Var
			if name == "" {
				name = r.Name
			}
			env.Vars[name] = r.Value
		case store.TierRun:
			name := e.Var
			if name == "" {
				name = r.Name
			}
			if r.Kind != store.KindFile {
				env.Vars[name] = r.Value
				continue
			}
			if env.FileDir == "" {
				dir, err := newDir(runtimeDir)
				if err != nil {
					env.Cleanup()
					return nil, err
				}
				env.FileDir = dir
			}
			p := filepath.Join(env.FileDir, r.Name)
			if err := os.WriteFile(p, []byte(r.Value), 0o600); err != nil {
				env.Cleanup()
				return nil, err
			}
			env.Vars[name] = p
		}
	}
	return env, nil
}

func newDir(base string) (string, error) {
	if base == "" {
		return "", fmt.Errorf("XDG_RUNTIME_DIR is not set; file secrets need a RAM-backed directory")
	}
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	dir := filepath.Join(base, "secretd-run", hex.EncodeToString(b))
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return "", err
	}
	return dir, os.Mkdir(dir, 0o700)
}

// Merge returns base with vars set (vars win).
func Merge(base []string, vars map[string]string) []string {
	out := make([]string, 0, len(base)+len(vars))
	for _, kv := range base {
		k, _, _ := strings.Cut(kv, "=")
		if _, ok := vars[k]; !ok {
			out = append(out, kv)
		}
	}
	for k, v := range vars {
		out = append(out, k+"="+v)
	}
	return out
}
