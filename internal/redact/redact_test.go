package redact

import (
	"bytes"
	"testing"
)

func TestWriterAcrossChunks(t *testing.T) {
	var out bytes.Buffer
	w := NewWriter(&out, "sk-SECRET-123")
	for _, chunk := range []string{"start sk-SEC", "RET-1", "23 middle sk-SECRET-123", " end"} {
		if _, err := w.Write([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), "start *** middle *** end"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestWriterOneByteAtATime(t *testing.T) {
	var out bytes.Buffer
	w := NewWriter(&out, "abc", "")
	for _, c := range []byte("xxabcxxab") {
		w.Write([]byte{c})
	}
	w.Flush()
	if got := out.String(); got != "xx***xxab" {
		t.Fatalf("got %q", got)
	}
}

func TestString(t *testing.T) {
	if got := String("key=v1 and v2", "v1", "v2", ""); got != "key=*** and ***" {
		t.Fatalf("got %q", got)
	}
}
