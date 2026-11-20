package agentcard

import (
	"encoding/json"
	"strings"
	"testing"
)

// mergeSigs returns the first card with all cards' signature entries, in
// order, as its signatures member.
func mergeSigs(t *testing.T, cards ...[]byte) []byte {
	t.Helper()
	var first map[string]any
	var all []any
	for i, c := range cards {
		var m map[string]any
		if err := json.Unmarshal(c, &m); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = m
		}
		all = append(all, m["signatures"].([]any)...)
	}
	first["signatures"] = all
	out, _ := json.Marshal(first)
	return out
}

func TestVerifyAnyOfIsOrderIndependent(t *testing.T) {
	pub, priv := newKey(t)
	anchors := []Anchor{{KID: "k1", Key: pub}}
	valid := signBody(t, testBody, priv, map[string]any{"alg": "EdDSA", "kid": "k1"})
	junk := map[string]map[string]any{
		"alg none":  {"alg": "none", "kid": "k1"},
		"jku":       {"alg": "EdDSA", "kid": "k1", "jku": "https://evil/k"},
		"jwk":       {"alg": "EdDSA", "kid": "k1", "jwk": map[string]any{"kty": "OKP"}},
		"crit":      {"alg": "EdDSA", "kid": "k1", "crit": []string{"x"}},
		"no kid":    {"alg": "EdDSA"},
		"other kid": {"alg": "EdDSA", "kid": "other"},
		"b64 false": {"alg": "EdDSA", "kid": "k1", "b64": false},
		"non-ASCII": {"alg": "EdDSA", "kid": "k1", "k\xc3\xa9y": 1},
	}
	for name, hdr := range junk {
		j := signBody(t, testBody, priv, hdr)
		for order, cards := range map[string][][]byte{"junk first": {j, valid}, "junk last": {valid, j}} {
			kid, err := Verify(mustParse(t, mergeSigs(t, cards...)), anchors)
			if err != nil || kid != "k1" {
				t.Errorf("%s, %s: kid=%q err=%v", name, order, kid, err)
			}
		}
		// A junk-only card never verifies.
		if _, err := Verify(mustParse(t, j), anchors); err == nil {
			t.Errorf("%s: junk-only card accepted", name)
		}
	}
}

func TestVerifyCoSigned(t *testing.T) {
	pub1, priv1 := newKey(t)
	_, priv2 := newKey(t)
	a := signBody(t, testBody, priv1, map[string]any{"alg": "EdDSA", "kid": "k1"})
	b := signBody(t, testBody, priv2, map[string]any{"alg": "EdDSA", "kid": "untrusted"})
	kid, err := Verify(mustParse(t, mergeSigs(t, b, a)), []Anchor{{KID: "k1", Key: pub1}})
	if err != nil || kid != "k1" {
		t.Fatalf("kid=%q err=%v", kid, err)
	}
}

func TestVerifyRejectsCaseVariantSignaturesMember(t *testing.T) {
	pub, priv := newKey(t)
	signed := signBody(t, testBody, priv, map[string]any{"alg": "EdDSA", "kid": "k1"})
	variant := []byte(strings.Replace(string(signed), `"signatures"`, `"Signatures"`, 1))
	if _, err := Verify(mustParse(t, variant), []Anchor{{KID: "k1", Key: pub}}); err == nil {
		t.Fatal("accepted a case-variant signatures member")
	}
}

func TestVerifyRejectsX5Headers(t *testing.T) {
	pub, priv := newKey(t)
	for _, h := range []string{"x5u", "x5c"} {
		b := signBody(t, testBody, priv, map[string]any{"alg": "EdDSA", "kid": "k1", h: "x"})
		if _, err := Verify(mustParse(t, b), []Anchor{{KID: "k1", Key: pub}}); err == nil {
			t.Errorf("accepted %s", h)
		}
	}
}

func TestParseRejectsNestedNonASCIIKey(t *testing.T) {
	in := `{"name":"a","capabilities":{"extensions":[{"uri":"u","params":{"tool` + "ſ" + `":1}}]}}`
	if _, err := Parse([]byte(in)); err == nil {
		t.Fatal("accepted a nested non-ASCII key")
	}
}

func TestRawIsACopy(t *testing.T) {
	c := mustParse(t, []byte(testBody))
	r := c.Raw()
	r[0] = 'X'
	if c.Raw()[0] != '{' {
		t.Fatal("Raw aliases the card's internal bytes")
	}
}

func TestSignedDigest(t *testing.T) {
	_, priv := newKey(t)
	a := mustParse(t, signBody(t, testBody, priv, map[string]any{"alg": "EdDSA", "kid": "k1"}))
	// Same body, different whitespace and escaping, no signatures.
	spaced := strings.NewReplacer(`{"name"`, "{ \"name\"", `"billing"`, `"bill`+"\x5c"+`u0069ng"`).Replace(testBody)
	b := mustParse(t, []byte(spaced))
	if a.SignedDigest() == "" || a.SignedDigest() != b.SignedDigest() {
		t.Fatalf("digests differ: %q vs %q", a.SignedDigest(), b.SignedDigest())
	}
	c := mustParse(t, []byte(strings.Replace(testBody, "sha256:aaa", "sha256:bbb", 1)))
	if c.SignedDigest() == a.SignedDigest() {
		t.Fatal("different bodies share a digest")
	}
	if (&Card{}).SignedDigest() != "" {
		t.Fatal("unparsed card has a digest")
	}
}
