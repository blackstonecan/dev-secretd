// Package state keeps the data of the daemon that is not secret: project
// locks and the audit log.
package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type State struct {
	mu     sync.Mutex
	dir    string
	Locked map[string]time.Time `json:"locked"` // project -> locked at
}

func Load(dir string) (*State, error) {
	st := &State{dir: dir, Locked: map[string]time.Time{}}
	raw, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, st); err != nil {
		return nil, err
	}
	if st.Locked == nil {
		st.Locked = map[string]time.Time{}
	}
	return st, nil
}

func (st *State) IsLocked(project string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	_, ok := st.Locked[project]
	return ok
}

func (st *State) SetLocked(project string, locked bool, now time.Time) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if locked {
		st.Locked[project] = now
	} else {
		delete(st.Locked, project)
	}
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(st.dir, ".state.json.tmp")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(st.dir, "state.json"))
}

// Audit appends JSON lines to <dir>/audit.log. It never records values.
type Audit struct {
	mu   sync.Mutex
	path string
}

func NewAudit(dir string) *Audit { return &Audit{path: filepath.Join(dir, "audit.log")} }

type Event struct {
	Time    time.Time `json:"time"`
	Op      string    `json:"op"`
	Project string    `json:"project,omitempty"`
	Name    string    `json:"name,omitempty"`
	Caller  string    `json:"caller,omitempty"` // uid and pid of the caller
	Detail  string    `json:"detail,omitempty"` // for proxy: method host path status
	Error   string    `json:"error,omitempty"`
}

func (a *Audit) Log(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	f, err := os.OpenFile(a.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(raw, '\n'))
}
