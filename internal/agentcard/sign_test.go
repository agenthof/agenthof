package agentcard

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

func signAndParse(t *testing.T, in string, kid string, priv ed25519.PrivateKey) (*Card, []byte) {
	t.Helper()
	out, err := Sign([]byte(in), kid, priv)
	if err != nil {
		t.Fatal(err)
	}
	return mustParse(t, out), out
}

func TestSignVerifiesAgainstMatchingAnchor(t *testing.T) {
	pub, priv := newKey(t)
	c, _ := signAndParse(t, testBody, "k1", priv)
	kid, err := Verify(c, []Anchor{{KID: "k1", Key: pub}})
	if err != nil || kid != "k1" {
		t.Fatalf("Verify = %q, %v; want k1, nil", kid, err)
	}
}

func TestSignRejectedByWrongKey(t *testing.T) {
	_, priv := newKey(t)
	otherPub, _ := newKey(t)
	c, _ := signAndParse(t, testBody, "k1", priv)
	if _, err := Verify(c, []Anchor{{KID: "k1", Key: otherPub}}); err == nil {
		t.Fatal("Verify accepted a signature from a different key")
	}
}

func TestSignStripsExistingSignatures(t *testing.T) {
	pub, priv := newKey(t)
	_, oldPriv := newKey(t)
	pre := signBody(t, testBody, oldPriv, map[string]any{"alg": "EdDSA", "kid": "old"})
	c, out := signAndParse(t, string(pre), "k1", priv)
	if kid, err := Verify(c, []Anchor{{KID: "k1", Key: pub}}); err != nil || kid != "k1" {
		t.Fatalf("Verify = %q, %v; want k1, nil", kid, err)
	}
	if n := len(c.Signatures); n != 1 {
		t.Fatalf("got %d signatures, want 1", n)
	}
	if strings.Contains(string(out), `"old"`) {
		t.Fatal("old signature survived")
	}
	if got, want := c.SignedDigest(), mustParse(t, []byte(testBody)).SignedDigest(); got != want {
		t.Fatalf("digest %s != stripped digest %s", got, want)
	}
}

func TestSignDigestStable(t *testing.T) {
	_, priv := newKey(t)
	c, _ := signAndParse(t, testBody, "k1", priv)
	if got, want := c.SignedDigest(), mustParse(t, []byte(testBody)).SignedDigest(); got == "" || got != want {
		t.Fatalf("signed digest %q != unsigned digest %q", got, want)
	}
}

func TestSignErrors(t *testing.T) {
	_, priv := newKey(t)
	if _, err := Sign([]byte("not json"), "k1", priv); err == nil {
		t.Error("Sign accepted non-JSON")
	}
	if _, err := Sign([]byte(testBody), "k1", priv[:10]); err == nil {
		t.Error("Sign accepted a short key")
	}
	if _, err := Sign([]byte(testBody), "k1", nil); err == nil {
		t.Error("Sign accepted a nil key")
	}
}
