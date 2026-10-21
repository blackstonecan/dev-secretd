package dotenv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sample = `# comment
PORT=3000
export API_KEY=sk-123 # trailing comment
QUOTED="a \"b\" c\nnext"
SINGLE='raw $value'
EMPTY=
`

func TestParse(t *testing.T) {
	entries, err := Parse(sample)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"PORT": "3000", "API_KEY": "sk-123", "QUOTED": "a \"b\" c\nnext", "SINGLE": "raw $value", "EMPTY": ""}
	if len(entries) != len(want) {
		t.Fatalf("got %d entries", len(entries))
	}
	for _, e := range entries {
		if want[e.Key] != e.Value {
			t.Errorf("%s = %q, want %q", e.Key, e.Value, want[e.Key])
		}
	}
	if _, err := Parse("not a line"); err == nil {
		t.Fatal("want parse error")
	}
}

func TestRemoveKeys(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(p, []byte(sample), 0o640); err != nil {
		t.Fatal(err)
	}
	entries, _ := Parse(sample)
	var remove []Entry
	for _, e := range entries {
		if e.Key == "API_KEY" {
			remove = append(remove, e)
		}
	}
	if err := RemoveKeys(p, remove, "moved to secretd"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	if strings.Contains(string(raw), "sk-123") || !strings.Contains(string(raw), "# API_KEY: moved to secretd") || !strings.Contains(string(raw), "PORT=3000") {
		t.Fatalf("rewritten file:\n%s", raw)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o640 {
		t.Fatalf("mode changed to %v", st.Mode().Perm())
	}
}
