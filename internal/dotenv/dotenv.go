// Package dotenv reads .env files and removes imported keys from them.
package dotenv

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

type Entry struct {
	Key   string
	Value string
	Line  int // 0-based line index in the file
}

var lineRe = regexp.MustCompile(`^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$`)

// Parse supports KEY=value, export KEY=value, 'single' and "double" quotes
// (with \n, \" and \\ escapes) and # comments.
func Parse(content string) ([]Entry, error) {
	var out []Entry
	for i, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		m := lineRe.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("line %d: cannot parse", i+1)
		}
		v, err := value(m[2])
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		out = append(out, Entry{Key: m[1], Value: v, Line: i})
	}
	return out, nil
}

func value(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(raw, "'"):
		end := strings.Index(raw[1:], "'")
		if end < 0 {
			return "", fmt.Errorf("missing closing quote")
		}
		return raw[1 : end+1], nil
	case strings.HasPrefix(raw, `"`):
		var b strings.Builder
		for i := 1; i < len(raw); i++ {
			c := raw[i]
			if c == '"' {
				return b.String(), nil
			}
			if c == '\\' && i+1 < len(raw) {
				i++
				switch raw[i] {
				case 'n':
					b.WriteByte('\n')
				default:
					b.WriteByte(raw[i])
				}
				continue
			}
			b.WriteByte(c)
		}
		return "", fmt.Errorf("missing closing quote")
	default:
		// An unquoted value ends at " #".
		if i := strings.Index(raw, " #"); i >= 0 {
			raw = raw[:i]
		}
		return strings.TrimSpace(raw), nil
	}
}

// RemoveKeys rewrites the file without the given lines. Each removed line
// becomes a comment that names the key, never the value.
func RemoveKeys(path string, entries []Entry, note string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(raw), "\n")
	for _, e := range entries {
		lines[e.Line] = fmt.Sprintf("# %s: %s", e.Key, note)
	}
	tmp := path + ".secretd.tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(lines, "\n")), st.Mode().Perm()); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
