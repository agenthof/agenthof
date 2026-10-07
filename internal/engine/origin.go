package engine

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Origin is where a run's request arrived from — provenance, not identity
// and not corroboration. The verified invoker is the who; Origin is the
// request channel's own account of itself, kept so an operator can ask
// "which path triggered this?". ForwardedFor is copied verbatim from
// X-Forwarded-For and is UNVERIFIED: anyone who can reach the server can
// set it. Stamped on workflow_started and run_refused only (the config_hash
// pattern), never on Binding. Additive and omitempty (Article VI): a run
// with no Origin — every CLI run — serializes exactly as before.
type Origin struct {
	Via          string `json:"via"` // "api" | "cli"
	RemoteAddr   string `json:"remote_addr,omitempty"`
	ForwardedFor string `json:"forwarded_for,omitempty"` // X-Forwarded-For, UNVERIFIED
	UserAgent    string `json:"user_agent,omitempty"`
	ServerHost   string `json:"server_host,omitempty"`
	// reserved: TLSPeer string — the only field that would be corroboration (an mTLS peer SAN)
}

// originFieldMax caps every Origin field, in runes. UserAgent and
// ForwardedFor are attacker-controlled request headers: an uncapped value
// cannot tear the JSONL line (json.Marshal escapes CR/LF) but it can
// poison a terminal render — the exec-argv-forgery class.
const originFieldMax = 200

// sanitized returns a copy of o with every field capped at originFieldMax
// runes and every non-printable rune removed. nil stays nil, so a CLI run's
// events are byte-identical to before Origin existed. Run applies it at
// entry, so no caller can write an unsanitized Origin.
func (o *Origin) sanitized() *Origin {
	if o == nil {
		return nil
	}
	c := *o
	c.Via = cleanOriginField(c.Via)
	c.RemoteAddr = cleanOriginField(c.RemoteAddr)
	c.ForwardedFor = cleanOriginField(c.ForwardedFor)
	c.UserAgent = cleanOriginField(c.UserAgent)
	c.ServerHost = cleanOriginField(c.ServerHost)
	return &c
}

func cleanOriginField(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if r == utf8.RuneError || !unicode.IsPrint(r) {
			continue
		}
		if n == originFieldMax {
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}
