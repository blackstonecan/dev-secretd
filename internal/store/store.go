// Package store keeps all secrets in one file, encrypted with AES-256-GCM.
//
// Only the secretd daemon user (and root) can read the file and the master
// key. Every operation reads the file again, so the daemon and the root
// commands (reveal, rotate, rm, bind) always see the same data. A file lock
// serializes writers.
package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Tier says how a secret may leave the daemon.
type Tier string

const (
	// TierProxy secrets never leave the daemon. The proxy adds them to
	// requests for the bound host only.
	TierProxy Tier = "proxy"
	// TierRun secrets go into the environment (or a temporary file) of a
	// process that `secret run` starts. Use dev-only values for them.
	TierRun Tier = "run"
	// TierPublic values are not secret: anyone may read them, the user may
	// change them, and a project without its own falls back to the user's.
	// They name things (a username, an org) and never go through the proxy.
	TierPublic Tier = "public"
)

// MaxPublicLen is the longest public value.
const MaxPublicLen = 4096

// Kind says how a run-tier value reaches the process.
type Kind string

const (
	KindEnv  Kind = "env"
	KindFile Kind = "file"
)

// Binding says where and how the proxy adds a proxy-tier secret.
type Binding struct {
	Host string `json:"host"` // upstream host, always HTTPS; the default host
	// More hosts the secret may go to. A proxy URL picks one with its first
	// path segment: /<project>/<NAME>/<host>/<path>.
	ExtraHosts []string `json:"extra_hosts,omitempty"`
	Header     string   `json:"header,omitempty"` // header name, for example x-api-key
	Format     string   `json:"format,omitempty"` // header value template, "{}" is the secret; default "{}"
	// Basic auth: the name of a public value that holds the username, looked
	// up in the secret's project and then the user scope at each request. The
	// header value is "Basic base64(<username>:<secret>)". Instead of Format;
	// git over HTTPS needs it.
	Basic string `json:"basic,omitempty"`
	Query string `json:"query,omitempty"` // query parameter name, instead of a header
}

// MaxHosts is the most hosts one binding may have.
const MaxHosts = 8

// Hosts returns the default host and then the extra hosts.
func (b *Binding) Hosts() []string { return append([]string{b.Host}, b.ExtraHosts...) }

// HeaderValue is the header value that carries the secret. username is the
// resolved public value named by Basic (unused without Basic).
func (b *Binding) HeaderValue(value, username string) string {
	if b.Basic != "" {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+value))
	}
	format := b.Format
	if format == "" {
		format = "{}"
	}
	return strings.Replace(format, "{}", value, 1)
}

// ParseHosts splits a --host list: "a.com,b.com" becomes a.com with b.com extra.
func ParseHosts(list string) (string, []string) {
	var hosts []string
	for _, h := range strings.Split(list, ",") {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}
	}
	if len(hosts) == 0 {
		return "", nil
	}
	return hosts[0], hosts[1:]
}

type Secret struct {
	Project string   `json:"project"`
	Name    string   `json:"name"`
	Tier    Tier     `json:"tier"`
	Kind    Kind     `json:"kind,omitempty"`
	Binding *Binding `json:"binding,omitempty"`
	Value   string   `json:"value"`
	// Default (user scope only): every project whose manifest lists the name
	// gets this secret when it has none of its own, unless its entry says
	// `fallback: none`.
	Default   bool      `json:"default,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Key is "project/NAME".
func (s *Secret) Key() string { return s.Project + "/" + s.Name }

var (
	projectRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	nameRe    = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)
	hostRe    = regexp.MustCompile(`^[a-zA-Z0-9.-]+(:[0-9]{1,5})?$`)
	headerRe  = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	queryRe   = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
)

// UserProject is the user scope: secrets that any project may fall back to
// when its manifest entry says `fallback: user` and it has no secret of the
// same name itself.
const UserProject = "user"

var (
	ErrNotFound = errors.New("secret not found")
	ErrExists   = errors.New("secret already exists (use `sudo secret rotate` to change it)")
)

func ValidProject(p string) bool { return projectRe.MatchString(p) }
func ValidName(n string) bool    { return nameRe.MatchString(n) }

// Validate checks a secret before it is written.
func (s *Secret) Validate() error {
	if !ValidProject(s.Project) {
		return fmt.Errorf("invalid project %q (lowercase letters, digits, . _ -)", s.Project)
	}
	if !ValidName(s.Name) {
		return fmt.Errorf("invalid name %q (UPPER_SNAKE_CASE)", s.Name)
	}
	if s.Value == "" {
		return errors.New("empty value")
	}
	if s.Default && s.Project != UserProject {
		return fmt.Errorf("only %s secrets can be a default", UserProject)
	}
	switch s.Tier {
	case TierProxy:
		if s.Kind != "" && s.Kind != KindEnv {
			return errors.New("a proxy-tier secret has no kind")
		}
		b := s.Binding
		if b == nil || !hostRe.MatchString(b.Host) {
			return errors.New("a proxy-tier secret needs a valid --host")
		}
		hosts := b.Hosts()
		if len(hosts) > MaxHosts {
			return fmt.Errorf("at most %d hosts", MaxHosts)
		}
		seen := map[string]bool{}
		for _, h := range hosts {
			if !hostRe.MatchString(h) {
				return fmt.Errorf("invalid host %q", h)
			}
			if seen[strings.ToLower(h)] {
				return fmt.Errorf("host %q is listed twice", h)
			}
			seen[strings.ToLower(h)] = true
		}
		if b.Basic != "" {
			if b.Header == "" || b.Format != "" {
				return errors.New("--basic needs --header and no --format")
			}
			if !ValidName(b.Basic) {
				return fmt.Errorf("--basic names a public value (UPPER_SNAKE_CASE), got %q", b.Basic)
			}
		}
		if (b.Header == "") == (b.Query == "") {
			return errors.New("a proxy-tier secret needs exactly one of --header or --query")
		}
		if b.Header != "" && !headerRe.MatchString(b.Header) {
			return fmt.Errorf("invalid header name %q", b.Header)
		}
		if b.Query != "" && !queryRe.MatchString(b.Query) {
			return fmt.Errorf("invalid query parameter name %q", b.Query)
		}
		if b.Format != "" && countPlaceholders(b.Format) != 1 {
			return errors.New(`--format must contain "{}" exactly once`)
		}
	case TierRun:
		if s.Binding != nil {
			return errors.New("a run-tier secret has no binding")
		}
		if s.Kind != KindEnv && s.Kind != KindFile {
			return errors.New("a run-tier secret needs kind env or file")
		}
	case TierPublic:
		if s.Binding != nil || s.Kind != "" {
			return errors.New("a public value has no binding and no kind")
		}
		if s.Default {
			return errors.New("public values always fall back to the user scope; they are not a default")
		}
		if len(s.Value) > MaxPublicLen {
			return fmt.Errorf("a public value has at most %d bytes", MaxPublicLen)
		}
	default:
		return fmt.Errorf("invalid tier %q (proxy, run or public)", s.Tier)
	}
	return nil
}

// ResolvePublic returns the public value NAME of a project, or of the user
// scope when the project has none. A private secret of that name is an error
// (and its value is never returned).
func (s *Store) ResolvePublic(project, name string) (*Secret, error) {
	sec, err := s.Get(project, name)
	if errors.Is(err, ErrNotFound) && project != UserProject {
		sec, err = s.Get(UserProject, name)
	}
	if err != nil {
		return nil, err
	}
	if sec.Tier != TierPublic {
		return nil, fmt.Errorf("%s is a private secret, not a public value", sec.Key())
	}
	return sec, nil
}

func countPlaceholders(s string) int {
	n := 0
	for i := 0; i+1 < len(s); i++ {
		if s[i] == '{' && s[i+1] == '}' {
			n++
		}
	}
	return n
}

// Store is the encrypted file plus its lock file.
type Store struct {
	path string
	key  []byte
}

const magic = "SECRETD1"

// Open uses <dir>/store.enc. The key must be 32 bytes.
func Open(dir string, key []byte) (*Store, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes, got %d", len(key))
	}
	return &Store{path: filepath.Join(dir, "store.enc"), key: key}, nil
}

type data struct {
	Secrets map[string]*Secret `json:"secrets"`
}

// View runs fn with a read lock.
func (s *Store) View(fn func(map[string]*Secret) error) error {
	unlock, err := s.lock(syscall.LOCK_SH)
	if err != nil {
		return err
	}
	defer unlock()
	d, err := s.read()
	if err != nil {
		return err
	}
	return fn(d.Secrets)
}

// Update runs fn with a write lock and saves the result if fn returns nil.
func (s *Store) Update(fn func(map[string]*Secret) error) error {
	unlock, err := s.lock(syscall.LOCK_EX)
	if err != nil {
		return err
	}
	defer unlock()
	d, err := s.read()
	if err != nil {
		return err
	}
	if err := fn(d.Secrets); err != nil {
		return err
	}
	return s.write(d)
}

// Get returns a copy of one secret.
func (s *Store) Get(project, name string) (*Secret, error) {
	var out *Secret
	err := s.View(func(m map[string]*Secret) error {
		sec, ok := m[project+"/"+name]
		if !ok {
			return ErrNotFound
		}
		c := *sec
		out = &c
		return nil
	})
	return out, err
}

// List returns copies of all secrets of a project ("" = all), sorted by key.
func (s *Store) List(project string) ([]Secret, error) {
	var out []Secret
	err := s.View(func(m map[string]*Secret) error {
		for _, sec := range m {
			if project == "" || sec.Project == project {
				out = append(out, *sec)
			}
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out, err
}

// Create adds a new secret. It never replaces one.
func (s *Store) Create(sec Secret, now time.Time) error {
	if err := sec.Validate(); err != nil {
		return err
	}
	sec.CreatedAt, sec.UpdatedAt = now, now
	return s.Update(func(m map[string]*Secret) error {
		if _, ok := m[sec.Key()]; ok {
			return ErrExists
		}
		m[sec.Key()] = &sec
		return nil
	})
}

// SetPublic creates a public value or changes an existing one. It never
// touches a private secret of the same name.
func (s *Store) SetPublic(project, name, value string, now time.Time) error {
	sec := Secret{Project: project, Name: name, Tier: TierPublic, Value: value, CreatedAt: now, UpdatedAt: now}
	if err := sec.Validate(); err != nil {
		return err
	}
	return s.Update(func(m map[string]*Secret) error {
		if old, ok := m[sec.Key()]; ok {
			if old.Tier != TierPublic {
				return fmt.Errorf("%s is a private secret: a name is either private or public", sec.Key())
			}
			sec.CreatedAt = old.CreatedAt
		}
		m[sec.Key()] = &sec
		return nil
	})
}

func (s *Store) lock(how int) (func(), error) {
	f, err := os.OpenFile(s.path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), how); err != nil {
		f.Close()
		return nil, err
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

func (s *Store) read() (*data, error) {
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return &data{Secrets: map[string]*Secret{}}, nil
	}
	if err != nil {
		return nil, err
	}
	plain, err := s.open(raw)
	if err != nil {
		return nil, err
	}
	d := &data{}
	if err := json.Unmarshal(plain, d); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	if d.Secrets == nil {
		d.Secrets = map[string]*Secret{}
	}
	return d, nil
}

func (s *Store) write(d *data) error {
	plain, err := json.Marshal(d)
	if err != nil {
		return err
	}
	sealed, err := s.seal(plain)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".store-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(sealed); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// Root commands keep the file owned by the daemon user.
	if os.Geteuid() == 0 {
		if st, err := os.Stat(filepath.Dir(s.path)); err == nil {
			sys := st.Sys().(*syscall.Stat_t)
			if err := os.Chown(tmp.Name(), int(sys.Uid), int(sys.Gid)); err != nil {
				return err
			}
		}
	}
	return os.Rename(tmp.Name(), s.path)
}

func (s *Store) aead() (cipher.AEAD, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (s *Store) seal(plain []byte) ([]byte, error) {
	g, err := s.aead()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte(magic), nonce...)
	return g.Seal(out, nonce, plain, []byte(magic)), nil
}

func (s *Store) open(raw []byte) ([]byte, error) {
	g, err := s.aead()
	if err != nil {
		return nil, err
	}
	if len(raw) < len(magic)+g.NonceSize() || string(raw[:len(magic)]) != magic {
		return nil, errors.New("store: not a secretd store file")
	}
	nonce := raw[len(magic) : len(magic)+g.NonceSize()]
	plain, err := g.Open(nil, nonce, raw[len(magic)+g.NonceSize():], []byte(magic))
	if err != nil {
		return nil, errors.New("store: cannot decrypt (wrong master key or damaged file)")
	}
	return plain, nil
}

// NewKey returns a random 32-byte master key.
func NewKey() ([]byte, error) {
	k := make([]byte, 32)
	_, err := rand.Read(k)
	return k, err
}
