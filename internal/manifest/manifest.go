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
//	  GITHUB_USERNAME:
//	    tier: public         # not secret; the project's value, else the user's
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
//	  GMAIL_TOKEN:
//	    tier: proxy
//	    optin: true          # only for `secret run --with GMAIL_TOKEN`
//	    env:
//	      GMAIL_API_BASE_URL: "{proxy}"
//
// `sudo secret bind P/GMAIL_TOKEN --run-key` makes the proxy serve a proxy
// secret only to the run that lists it: "{proxy}" then carries the run's key.
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
	"strings"

	"github.com/blackstonecan/dev-secretd/internal/store"
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
	// Optin: `secret run` skips this entry unless the command names it
	// (`secret run --with NAME` or `--only NAME`). For a secret only one of
	// the project's processes needs.
	Optin bool `yaml:"optin,omitempty"`
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
		case store.TierRun, store.TierPublic:
			if len(e.Env) != 0 {
				return fmt.Errorf("%s: %s: a %s entry has var, not env", m.Path, name, e.Tier)
			}
			if e.Var != "" && !envRe.MatchString(e.Var) {
				return fmt.Errorf("%s: %s: invalid var %q", m.Path, name, e.Var)
			}
		default:
			return fmt.Errorf("%s: %s: tier must be proxy, run or public", m.Path, name)
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

// Select returns the names a `secret run` command gets, sorted. With only,
// exactly those names; otherwise every entry that is not opt-in, plus the
// names in with. Every name given must be an entry.
func (m *Manifest) Select(only, with []string) ([]string, error) {
	if len(only) > 0 && len(with) > 0 {
		return nil, errors.New("use --only or --with, not both")
	}
	for _, n := range append(append([]string{}, only...), with...) {
		if _, ok := m.Secrets[n]; !ok {
			return nil, fmt.Errorf("%s is not in %s", n, m.Path)
		}
	}
	if len(only) > 0 {
		out := append([]string{}, only...)
		sort.Strings(out)
		return out, nil
	}
	pick := map[string]bool{}
	for _, n := range with {
		pick[n] = true
	}
	var out []string
	for n, e := range m.Secrets {
		if !e.Optin || pick[n] {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out, nil
}

// SplitList splits a comma-separated flag value, dropping blanks.
func SplitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
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
