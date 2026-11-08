// Package runkey keeps the per-run keys of `secret run`.
//
// A proxy secret with the run_key flag is served only to requests that carry
// a live key. The daemon gives a key to one `secret run` process and drops it
// when that process ends (its connection closes), when the project is locked,
// or when the daemon stops. Keys live in memory only. A key is never logged
// and never part of an error.
package runkey

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
)

// Registry holds the live keys. Its map is indexed by the SHA-256 of the key,
// so a lookup never compares the plain key.
type Registry struct {
	mu   sync.Mutex
	runs map[string]*Run
}

// Run is one `secret run` process and the secrets its key covers.
type Run struct {
	hash    string
	secrets map[string]bool // "project/NAME"
	done    chan struct{}
	once    sync.Once
}

func New() *Registry { return &Registry{runs: map[string]*Run{}} }

func hash(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// Issue makes a key (64 hex chars) that covers the given "project/NAME" secrets.
func (r *Registry) Issue(secrets []string) (string, *Run, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	key := hex.EncodeToString(raw)
	run := &Run{hash: hash(key), secrets: map[string]bool{}, done: make(chan struct{})}
	for _, s := range secrets {
		run.secrets[s] = true
	}
	r.mu.Lock()
	r.runs[run.hash] = run
	r.mu.Unlock()
	return key, run, nil
}

// Valid reports whether key is live and covers project/name. A nil Registry
// has no keys.
func (r *Registry) Valid(key, project, name string) bool {
	if r == nil || key == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	run, ok := r.runs[hash(key)]
	return ok && run.secrets[project+"/"+name]
}

// Revoke removes a run and closes its Done channel. It is safe to call twice.
func (r *Registry) Revoke(run *Run) {
	if r == nil || run == nil {
		return
	}
	r.mu.Lock()
	delete(r.runs, run.hash)
	r.mu.Unlock()
	run.once.Do(func() { close(run.done) })
}

// RevokeProject revokes every run that covers a secret of project. It returns
// how many runs it revoked.
func (r *Registry) RevokeProject(project string) int {
	if r == nil {
		return 0
	}
	var hit []*Run
	r.mu.Lock()
	for _, run := range r.runs {
		for s := range run.secrets {
			if strings.HasPrefix(s, project+"/") {
				hit = append(hit, run)
				break
			}
		}
	}
	r.mu.Unlock()
	for _, run := range hit {
		r.Revoke(run)
	}
	return len(hit)
}

// RevokeAll revokes every run (the daemon is stopping).
func (r *Registry) RevokeAll() {
	if r == nil {
		return
	}
	r.mu.Lock()
	all := make([]*Run, 0, len(r.runs))
	for _, run := range r.runs {
		all = append(all, run)
	}
	r.mu.Unlock()
	for _, run := range all {
		r.Revoke(run)
	}
}

// Count is the number of live runs.
func (r *Registry) Count() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.runs)
}

// Done is closed when the run is revoked.
func (run *Run) Done() <-chan struct{} { return run.done }
