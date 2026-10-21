// Package redact replaces secret values in a byte stream, also when a value
// is split across two writes.
package redact

import (
	"bytes"
	"io"
)

const Mask = "***"

// Writer replaces each value with Mask before the bytes reach w. It holds
// back the last len(longest value)-1 bytes until the next Write or Flush.
type Writer struct {
	w       io.Writer
	values  [][]byte
	keep    int
	pending []byte
}

// NewWriter ignores empty values.
func NewWriter(w io.Writer, values ...string) *Writer {
	rw := &Writer{w: w}
	for _, v := range values {
		if v == "" {
			continue
		}
		rw.values = append(rw.values, []byte(v))
		if len(v)-1 > rw.keep {
			rw.keep = len(v) - 1
		}
	}
	return rw
}

func (rw *Writer) Write(p []byte) (int, error) {
	rw.pending = append(rw.pending, p...)
	rw.pending = rw.replace(rw.pending)
	if len(rw.pending) > rw.keep {
		cut := len(rw.pending) - rw.keep
		if _, err := rw.w.Write(rw.pending[:cut]); err != nil {
			return 0, err
		}
		rw.pending = append(rw.pending[:0], rw.pending[cut:]...)
	}
	return len(p), nil
}

// Flush writes the held-back bytes. Call it at the end of the stream.
func (rw *Writer) Flush() error {
	if len(rw.pending) == 0 {
		return nil
	}
	_, err := rw.w.Write(rw.pending)
	rw.pending = rw.pending[:0]
	return err
}

func (rw *Writer) replace(b []byte) []byte {
	for _, v := range rw.values {
		if bytes.Contains(b, v) {
			b = bytes.ReplaceAll(b, v, []byte(Mask))
		}
	}
	return b
}

// String replaces each value in s.
func String(s string, values ...string) string {
	b := []byte(s)
	for _, v := range values {
		if v != "" {
			b = bytes.ReplaceAll(b, []byte(v), []byte(Mask))
		}
	}
	return string(b)
}
