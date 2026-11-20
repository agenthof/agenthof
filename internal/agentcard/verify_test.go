package agentcard

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

var b64 = base64.RawURLEncoding

const testBody = `{"name":"billing","description":"d","version":"1","capabilities":{"extensions":[{"uri":"https://agenthof.dev/ext/agent/v1","params":{"artifact":"img@sha256:aaa"}}]}}`

// signBody signs the JCS of body (a JSON object) and returns the card JSON
// with a signatures member carrying the given protected header.
func signBody(t *testing.T, body string, priv ed25519.PrivateKey, protected map[string]any) []byte {
	t.Helper()
	canon, err := jcsRaw([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	ph, _ := json.Marshal(protected)
	p := b64.EncodeToString(ph)
	sig := ed25519.Sign(priv, []byte(p+"."+b64.EncodeToString(canon)))
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatal(err)
	}
	m["signatures"] = []map[string]string{{"protected": p, "signature": b64.EncodeToString(sig)}}
	out, _ := json.Marshal(m)
	return out
}

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func mustParse(t *testing.T, b []byte) *Card {
	t.Helper()
	c, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestVerifyGoodSignature(t *testing.T) {
	pub, priv := newKey(t)
	other, _ := newKey(t)
	card := mustParse(t, signBody(t, testBody, priv, map[string]any{"alg": "EdDSA", "kid": "k1", "typ": "JOSE"}))
	kid, err := Verify(card, []Anchor{{KID: "k0", Key: other}, {KID: "k1", Key: pub}})
	if err != nil || kid != "k1" {
		t.Fatalf("kid=%q err=%v", kid, err)
	}
}

func TestVerifyAnyOf(t *testing.T) {
	_, priv1 := newKey(t)
	pub2, priv2 := newKey(t)
	// Two signatures: first by an untrusted kid, second by a trusted one.
	c1 := signBody(t, testBody, priv1, map[string]any{"alg": "EdDSA", "kid": "untrusted"})
	c2 := signBody(t, testBody, priv2, map[string]any{"alg": "EdDSA", "kid": "k2"})
	var m1, m2 map[string]any
	_ = json.Unmarshal(c1, &m1)
	_ = json.Unmarshal(c2, &m2)
	m1["signatures"] = append(m1["signatures"].([]any), m2["signatures"].([]any)...)
	b, _ := json.Marshal(m1)
	kid, err := Verify(mustParse(t, b), []Anchor{{KID: "k2", Key: pub2}})
	if err != nil || kid != "k2" {
		t.Fatalf("kid=%q err=%v", kid, err)
	}
}

func TestVerifyRejects(t *testing.T) {
	pub, priv := newKey(t)
	other, otherPriv := newKey(t)
	good := map[string]any{"alg": "EdDSA", "kid": "k1"}
	anchors := []Anchor{{KID: "k1", Key: pub}}

	signed := signBody(t, testBody, priv, good)
	tampered := []byte(strings.Replace(string(signed), "sha256:aaa", "sha256:bbb", 1))

	cases := []struct {
		name    string
		card    []byte
		anchors []Anchor
	}{
		{"tampered body", tampered, anchors},
		{"no anchors", signed, nil},
		{"empty anchors", signed, []Anchor{}},
		{"no signature", []byte(testBody), anchors},
		{"empty signatures", []byte(strings.TrimSuffix(testBody, "}") + `,"signatures":[]}`), anchors},
		{"jku", signBody(t, testBody, priv, map[string]any{"alg": "EdDSA", "kid": "k1", "jku": "https://evil/keys"}), anchors},
		{"jwk", signBody(t, testBody, priv, map[string]any{"alg": "EdDSA", "kid": "k1", "jwk": map[string]any{"kty": "OKP"}}), anchors},
		{"alg none", signBody(t, testBody, priv, map[string]any{"alg": "none", "kid": "k1"}), anchors},
		{"alg HS256", signBody(t, testBody, priv, map[string]any{"alg": "HS256", "kid": "k1"}), anchors},
		{"alg missing", signBody(t, testBody, priv, map[string]any{"kid": "k1"}), anchors},
		{"alg lowercase", signBody(t, testBody, priv, map[string]any{"alg": "eddsa", "kid": "k1"}), anchors},
		{"crit", signBody(t, testBody, priv, map[string]any{"alg": "EdDSA", "kid": "k1", "crit": []string{"x"}, "x": 1}), anchors},
		{"untrusted kid", signBody(t, testBody, priv, map[string]any{"alg": "EdDSA", "kid": "nope"}), anchors},
		{"missing kid", signBody(t, testBody, priv, map[string]any{"alg": "EdDSA"}), anchors},
		{"trusted kid wrong key", signBody(t, testBody, otherPriv, good), anchors},
		{"anchor key wrong", signed, []Anchor{{KID: "k1", Key: other}}},
		{"anchor key bad length", signed, []Anchor{{KID: "k1", Key: ed25519.PublicKey("short")}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if kid, err := Verify(mustParse(t, tc.card), tc.anchors); err == nil {
				t.Fatalf("accepted (kid %q)", kid)
			}
		})
	}
}

func TestVerifyRejectsUnparsedCard(t *testing.T) {
	pub, _ := newKey(t)
	if _, err := Verify(&Card{}, []Anchor{{KID: "k", Key: pub}}); err == nil {
		t.Fatal("accepted a card that was not produced by Parse")
	}
	if _, err := Verify(nil, []Anchor{{KID: "k", Key: pub}}); err == nil {
		t.Fatal("accepted nil card")
	}
}

func TestVerifyRejectsUnprotectedHeaderKeyMaterial(t *testing.T) {
	pub, priv := newKey(t)
	b := signBody(t, testBody, priv, map[string]any{"alg": "EdDSA", "kid": "k1"})
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	sigs := m["signatures"].([]any)
	sigs[0].(map[string]any)["header"] = map[string]any{"jwk": map[string]any{"kty": "OKP"}}
	out, _ := json.Marshal(m)
	if _, err := Verify(mustParse(t, out), []Anchor{{KID: "k1", Key: pub}}); err == nil {
		t.Fatal("accepted jwk in the unprotected header")
	}
}
