// Package manifest reads secrets.yaml: the names a project needs and how the
// app gets them. It holds no values. The store, not the manifest, decides the
// tier and the binding of each secret.
//
//	project: blackr-core
//	secrets:
//	  ANTHROPIC_API_KEY:
//	    tier: proxy
//	    env:
//	      ANTHROPIC_BASE_URL: "{proxy}"
//	      ANTHROPIC_API_KEY: placeholder
//	  POSTGRES_PASSWORD:
//	    tier: run            # var defaults to the secret name
//	  FIREBASE_ADMIN:
//	    tier: run
//	    var: GOOGLE_APPLICATION_CREDENTIALS   # a file secret: the var holds the path
//	  NPM_TOKEN:
//	    tier: run
//	    fallback: user       # use user/NPM_TOKEN when this project has none
//	  GITHUB_TOKEN:
//	    tier: proxy
//	    fallback: none       # never a user-scope default: this project needs its own
//	    env:
//	      GITHUB_API_URL: "{proxy}"
//
// The user manifest (UserPath) has `project: user` and lists the user-scope
// secrets for `secret run --user`.
package manifest

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"github.com/blackstonecan/secretd/internal/store"
	"gopkg.in/yaml.v3"
)

const FileName = "secrets.yaml"

type Entry struct {
	Tier store.Tier        `yaml:"tier"`
	Env  map[string]string `yaml:"env,omitempty"` // proxy tier: env vars; "{proxy}" is the base URL
	Var  string            `yaml:"var,omitempty"` // run tier: env var name (default: the secret name)
	// When the project has no secret of its own: "user" uses the user-scope
	// secret, "none" never falls back, and empty uses the user-scope secret
	// only if it is a default. A project secret of the same name always wins.
	Fallback string `yaml:"fallback,omitempty"`
}

type Manifest struct {
	Project string           `yaml:"project"`
	Secrets map[string]Entry `yaml:"secrets"`
	Path    string           `yaml:"-"`
}

var envRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Find looks for secrets.yaml in dir and its parents.
func Find(dir string) (*Manifest, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	for {
		p := filepath.Join(dir, FileName)
		if _, err := os.Stat(p); err == nil {
			return Load(p)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil, os.ErrNotExist
		}
		dir = parent
	}
}

func Load(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m := &Manifest{}
	if err := yaml.Unmarshal(raw, m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	m.Path = path
	if m.Secrets == nil {
		m.Secrets = map[string]Entry{}
	}
	return m, m.Validate()
}

func (m *Manifest) Validate() error {
	if !store.ValidProject(m.Project) {
		return fmt.Errorf("%s: invalid project %q", m.Path, m.Project)
	}
	for name, e := range m.Secrets {
		if !store.ValidName(name) {
			return fmt.Errorf("%s: invalid secret name %q", m.Path, name)
		}
		switch e.Tier {
		case store.TierProxy:
			if len(e.Env) == 0 || e.Var != "" {
				return fmt.Errorf("%s: %s: a proxy entry needs env (and no var)", m.Path, name)
			}
			for k := range e.Env {
				if !envRe.MatchString(k) {
					return fmt.Errorf("%s: %s: invalid env var %q", m.Path, name, k)
				}
			}
		case store.TierRun:
			if len(e.Env) != 0 {
				return fmt.Errorf("%s: %s: a run entry has var, not env", m.Path, name)
			}
			if e.Var != "" && !envRe.MatchString(e.Var) {
				return fmt.Errorf("%s: %s: invalid var %q", m.Path, name, e.Var)
			}
		default:
			return fmt.Errorf("%s: %s: tier must be proxy or run", m.Path, name)
		}
		if e.Fallback != "" {
			if e.Fallback != store.UserProject && e.Fallback != "none" {
				return fmt.Errorf("%s: %s: fallback must be %q or \"none\"", m.Path, name, store.UserProject)
			}
			if m.Project == store.UserProject {
				return fmt.Errorf("%s: %s: the user manifest has no fallback", m.Path, name)
			}
		}
	}
	return nil
}

// UserPath is the user manifest: $XDG_CONFIG_HOME/secretd/user.yaml, or
// ~/.config/secretd/user.yaml.
func UserPath() (string, error) {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "secretd", "user.yaml"), nil
}

// LoadUser reads the user manifest, which must say `project: user`.
func LoadUser() (*Manifest, error) {
	p, err := UserPath()
	if err != nil {
		return nil, err
	}
	m, err := Load(p)
	if err != nil {
		return nil, err
	}
	if m.Project != store.UserProject {
		return nil, fmt.Errorf("%s: project must be %q", p, store.UserProject)
	}
	return m, nil
}

// Names returns the secret names, sorted.
func (m *Manifest) Names() []string {
	out := make([]string, 0, len(m.Secrets))
	for n := range m.Secrets {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Save writes the manifest. Comments in an old file are not kept.
func (m *Manifest) Save() error {
	if m.Path == "" {
		return errors.New("manifest has no path")
	}
	raw, err := yaml.Marshal(m)
	if err != nil {
		return err
	}
	header := "# secretd manifest: names and rules only, never values. Safe to commit.\n"
	return os.WriteFile(m.Path, append([]byte(header), raw...), 0o644)
}
