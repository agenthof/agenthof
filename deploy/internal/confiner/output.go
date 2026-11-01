package confiner

import "bytes"

// MaxOutput caps the combined stdout+stderr a compartment can hand back:
// what is returned is what the agent gets and what output_sha covers.
const MaxOutput = 1 << 20

// TruncationMarker ends a capped output, so the agent sees that it is
// partial without parsing the response's truncated flag.
const TruncationMarker = "\n[output truncated by refexec]\n"

// CapWriter keeps the first max bytes written and counts every byte. It is
// the compartment's combined stdout+stderr: exec.Cmd serializes writes to a
// shared non-*os.File writer, so no lock is needed.
type CapWriter struct {
	max   int
	buf   bytes.Buffer
	total int64
}

// NewCapWriter returns a CapWriter that keeps at most max bytes.
func NewCapWriter(max int) *CapWriter { return &CapWriter{max: max} }

// Write keeps what fits under the cap and counts all of p.
func (c *CapWriter) Write(p []byte) (int, error) {
	c.total += int64(len(p))
	if room := c.max - c.buf.Len(); room > 0 {
		keep := p
		if len(keep) > room {
			keep = keep[:room]
		}
		c.buf.Write(keep)
	}
	return len(p), nil
}

// Output returns what is handed back: the kept bytes, plus the marker when
// anything was dropped, and whether anything was dropped.
func (c *CapWriter) Output() ([]byte, bool) {
	if c.total > int64(c.max) {
		return append(c.buf.Bytes(), TruncationMarker...), true
	}
	return c.buf.Bytes(), false
}

// Total is the number of bytes written, kept or not.
func (c *CapWriter) Total() int64 { return c.total }
