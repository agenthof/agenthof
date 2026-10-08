// Package origin is the request channel's account of itself: where a run
// or a control action arrived from. It is provenance, not identity and not
// corroboration — the verified invoker is the who; Origin is the way in.
// It is a leaf package (no imports beyond the standard library) so both
// ledgers, the engine and the API can share one type without the control
// ledger depending on the run engine.
package origin

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Origin is where a request arrived from. ForwardedFor is copied verbatim
// from X-Forwarded-For and is UNVERIFIED: anyone who can reach the server
// can set it. Additive and omitempty wherever it is embedded (Article VI):
// a record with no Origin — every CLI run, every CLI control action —
// serializes exactly as before the field existed.
type Origin struct {
	Via          string `json:"via"` // "api" | "cli"
	RemoteAddr   string `json:"remote_addr,omitempty"`
	ForwardedFor string `json:"forwarded_for,omitempty"` // X-Forwarded-For, UNVERIFIED
	UserAgent    string `json:"user_agent,omitempty"`
	ServerHost   string `json:"server_host,omitempty"`
	// reserved: TLSPeer string — the only field that would be corroboration (an mTLS peer SAN)
}

// fieldMax caps every Origin field, in runes. UserAgent and ForwardedFor
// are attacker-controlled request headers: an uncapped value cannot tear a
// JSONL line (json.Marshal escapes CR/LF) but it can poison a terminal
// render — the exec-argv-forgery class.
const fieldMax = 200

// Sanitized returns a copy of o with every field capped at fieldMax runes
// and every non-printable rune removed. nil stays nil. Every writer
// (engine.Run, engine.RecordRefused, control.Append) applies it at entry,
// so no caller can write an unsanitized Origin.
func (o *Origin) Sanitized() *Origin {
	if o == nil {
		return nil
	}
	c := *o
	c.Via = Clean(c.Via)
	c.RemoteAddr = Clean(c.RemoteAddr)
	c.ForwardedFor = Clean(c.ForwardedFor)
	c.UserAgent = Clean(c.UserAgent)
	c.ServerHost = Clean(c.ServerHost)
	return &c
}

// Clean is the one rule for an untrusted string headed for a ledger, a log
// or an HTTP body: printable runes only (invalid UTF-8 dropped), at most
// fieldMax runes. A string that is already printable and short comes back
// byte-identical.
func Clean(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if r == utf8.RuneError || !unicode.IsPrint(r) {
			continue
		}
		if n == fieldMax {
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}
