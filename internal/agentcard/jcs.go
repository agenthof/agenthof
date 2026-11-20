package agentcard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// jcsRaw canonicalizes a JSON document per RFC 8785.
func jcsRaw(b []byte) ([]byte, error) {
	if err := checkJSONStrings(b); err != nil {
		return nil, err
	}
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
		return jcsString(buf, t)
	case json.Number:
		f, err := strconv.ParseFloat(string(t), 64)
		if err != nil {
			return fmt.Errorf("canonicalize: number %q: %w", t, err)
		}
		if err := checkExactInteger(string(t), f); err != nil {
			return err
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
			if err := jcsString(buf, m.key); err != nil {
				return err
			}
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

func jcsString(buf *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return errors.New("canonicalize: string is not valid UTF-8")
	}
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
	return nil
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

// checkExactInteger rejects an integer literal that float64 cannot hold
// exactly: RFC 8785 numbers are IEEE 754 doubles, so signing such a value
// would silently canonicalize a rounded one.
func checkExactInteger(lit string, f float64) error {
	if strings.ContainsAny(lit, ".eE") {
		return nil
	}
	n, ok := new(big.Int).SetString(lit, 10)
	if !ok {
		return fmt.Errorf("canonicalize: number %q", lit)
	}
	if new(big.Float).SetInt(n).Cmp(big.NewFloat(f)) != 0 {
		return fmt.Errorf("canonicalize: integer %s is not exactly representable as a float64", lit)
	}
	return nil
}

// checkJSONStrings rejects what encoding/json would silently repair: invalid
// UTF-8 and unpaired surrogate escapes (RFC 8785 requires an error).
func checkJSONStrings(b []byte) error {
	if !utf8.Valid(b) {
		return errors.New("canonicalize: input is not valid UTF-8")
	}
	hex4 := func(i int) (rune, bool) {
		if i+4 > len(b) {
			return 0, false
		}
		// bitSize 16: a \uXXXX escape is exactly one UTF-16 code unit (<= 0xFFFF),
		// so the parsed value provably fits in a rune without an overflow check.
		v, err := strconv.ParseUint(string(b[i:i+4]), 16, 16)
		return rune(v), err == nil
	}
	inStr := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if !inStr {
			inStr = c == '"'
			continue
		}
		switch c {
		case '"':
			inStr = false
		case '\\':
			i++
			if i >= len(b) || b[i] != 'u' {
				continue
			}
			r, ok := hex4(i + 1)
			if !ok {
				return errors.New("canonicalize: bad unicode escape")
			}
			i += 4
			switch {
			case utf16.IsSurrogate(r) && r >= 0xdc00:
				return errors.New("canonicalize: unpaired low surrogate escape")
			case utf16.IsSurrogate(r):
				if i+2 >= len(b) || b[i+1] != '\\' || b[i+2] != 'u' {
					return errors.New("canonicalize: unpaired high surrogate escape")
				}
				lo, ok := hex4(i + 3)
				if !ok || lo < 0xdc00 || lo > 0xdfff {
					return errors.New("canonicalize: unpaired high surrogate escape")
				}
				i += 6
			}
		}
	}
	return nil
}
