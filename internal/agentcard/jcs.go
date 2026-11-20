package agentcard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// jcsRaw canonicalizes a JSON document per RFC 8785.
func jcsRaw(b []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("canonicalize: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("canonicalize: trailing data after the JSON value")
	}
	return jcs(v)
}

// jcs canonicalizes a value decoded by encoding/json (with UseNumber) per
// RFC 8785: object members sorted by UTF-16 code units, no insignificant
// whitespace, ECMAScript number formatting, minimal string escaping.
func jcs(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := jcsWrite(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func jcsWrite(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		buf.WriteString(strconv.FormatBool(t))
	case string:
		jcsString(buf, t)
	case json.Number:
		f, err := strconv.ParseFloat(string(t), 64)
		if err != nil {
			return fmt.Errorf("canonicalize: number %q: %w", t, err)
		}
		return jcsNumber(buf, f)
	case float64:
		return jcsNumber(buf, t)
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := jcsWrite(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		type member struct {
			key   string
			units []uint16
		}
		ms := make([]member, 0, len(t))
		for k := range t {
			ms = append(ms, member{k, utf16.Encode([]rune(k))})
		}
		sort.Slice(ms, func(i, j int) bool {
			a, b := ms[i].units, ms[j].units
			for n := 0; n < len(a) && n < len(b); n++ {
				if a[n] != b[n] {
					return a[n] < b[n]
				}
			}
			return len(a) < len(b)
		})
		buf.WriteByte('{')
		for i, m := range ms {
			if i > 0 {
				buf.WriteByte(',')
			}
			jcsString(buf, m.key)
			buf.WriteByte(':')
			if err := jcsWrite(buf, t[m.key]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("canonicalize: unsupported type %T", v)
	}
	return nil
}

func jcsString(buf *bytes.Buffer, s string) {
	const hex = "0123456789abcdef"
	buf.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			buf.WriteString(`\"`)
		case r == '\\':
			buf.WriteString(`\\`)
		case r == '\b':
			buf.WriteString(`\b`)
		case r == '\f':
			buf.WriteString(`\f`)
		case r == '\n':
			buf.WriteString(`\n`)
		case r == '\r':
			buf.WriteString(`\r`)
		case r == '\t':
			buf.WriteString(`\t`)
		case r < 0x20:
			buf.WriteString(`\u00`)
			buf.WriteByte(hex[r>>4])
			buf.WriteByte(hex[r&0xf])
		default:
			buf.WriteRune(r)
		}
	}
	buf.WriteByte('"')
}

// jcsNumber writes f in the ECMAScript Number-to-string form RFC 8785 requires.
func jcsNumber(buf *bytes.Buffer, f float64) error {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return errors.New("canonicalize: non-finite number")
	}
	if f == 0 {
		buf.WriteByte('0') // also folds -0
		return nil
	}
	if f < 0 {
		buf.WriteByte('-')
		f = -f
	}
	// Shortest round-trip digits as d.ddde±xx, then re-laid-out per ES6.
	s := strconv.FormatFloat(f, 'e', -1, 64)
	mant, expStr, _ := strings.Cut(s, "e")
	digits := strings.Replace(mant, ".", "", 1)
	exp, err := strconv.Atoi(expStr)
	if err != nil {
		return fmt.Errorf("canonicalize: number format: %w", err)
	}
	k, n := len(digits), exp+1
	switch {
	case k <= n && n <= 21:
		buf.WriteString(digits)
		buf.WriteString(strings.Repeat("0", n-k))
	case 0 < n && n <= 21:
		buf.WriteString(digits[:n])
		buf.WriteByte('.')
		buf.WriteString(digits[n:])
	case -6 < n && n <= 0:
		buf.WriteString("0.")
		buf.WriteString(strings.Repeat("0", -n))
		buf.WriteString(digits)
	default:
		buf.WriteString(digits[:1])
		if k > 1 {
			buf.WriteByte('.')
			buf.WriteString(digits[1:])
		}
		buf.WriteByte('e')
		e := n - 1
		if e < 0 {
			buf.WriteByte('-')
			e = -e
		} else {
			buf.WriteByte('+')
		}
		buf.WriteString(strconv.Itoa(e))
	}
	return nil
}
