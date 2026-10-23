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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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
)

// Kind says how a run-tier value reaches the process.
type Kind string

const (
	KindEnv  Kind = "env"
	KindFile Kind = "file"
)

// Binding says where and how the proxy adds a proxy-tier secret.
type Binding struct {
	Host   string `json:"host"`             // upstream host, always HTTPS
	Header string `json:"header,omitempty"` // header name, for example x-api-key
	Format string `json:"format,omitempty"` // header value template, "{}" is the secret; default "{}"
	Query  string `json:"query,omitempty"`  // query parameter name, instead of a header
}

type Secret struct {
	Project   string    `json:"project"`
	Name      string    `json:"name"`
	Tier      Tier      `json:"tier"`
	Kind      Kind      `json:"kind,omitempty"`
	Binding   *Binding  `json:"binding,omitempty"`
	Value     string    `json:"value"`
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
	switch s.Tier {
	case TierProxy:
		if s.Kind != "" && s.Kind != KindEnv {
			return errors.New("a proxy-tier secret has no kind")
		}
		b := s.Binding
		if b == nil || !hostRe.MatchString(b.Host) {
			return errors.New("a proxy-tier secret needs a valid --host")
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
	default:
		return fmt.Errorf("invalid tier %q (proxy or run)", s.Tier)
	}
	return nil
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
