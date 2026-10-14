package anchor

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/note"
)

// signNote builds a sumdb note the way Rekor signs a checkpoint: text, a
// blank line, then one "— <name> base64(keyhash ‖ ASN.1 ECDSA over sha256(text))"
// line. A test-local helper; the fake in anchortest has its own.
func signNote(t *testing.T, priv *ecdsa.PrivateKey, name, text string) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	d := sha256.Sum256([]byte(text))
	sig, err := ecdsa.SignASN1(rand.Reader, priv, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return []byte(text + "\n— " + name + " " + base64.StdEncoding.EncodeToString(append(sum[:4:4], sig...)) + "\n")
}

func pemPKIX(t *testing.T, pub any) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// flipSignature flips one byte INSIDE the decoded signature of the note's last
// signature line — past the 4-byte key hash — and re-encodes it, so the key
// hash still matches and only the signature is wrong. (Flipping a base64
// character instead can yield an invalid character and a malformed note.)
func flipSignature(t *testing.T, msg []byte) []byte {
	t.Helper()
	i := bytes.LastIndex(msg, []byte("\n— "))
	if i < 0 {
		t.Fatal("no signature line")
	}
	name, b64, _ := strings.Cut(strings.TrimPrefix(string(msg[i+1:len(msg)-1]), "— "), " ")
	sig, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	sig[len(sig)-1] ^= 0x01
	return append(msg[:i+1:i+1], []byte("— "+name+" "+base64.StdEncoding.EncodeToString(sig)+"\n")...)
}

// TestKeyHashAndIDMatchIndependentVectors: KeyHash is the big-endian uint32
// of sha256(PKIX DER)[:4] and KeyID the hex of the whole digest — Rekor's
// logID — both recomputed here without the package.
func TestKeyHashAndIDMatchIndependentVectors(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	sum := sha256.Sum256(der)
	h, err := KeyHash(&priv.PublicKey)
	if err != nil || h != binary.BigEndian.Uint32(sum[:4]) {
		t.Fatalf("KeyHash = %08x, %v; want %08x", h, err, binary.BigEndian.Uint32(sum[:4]))
	}
	id, err := KeyID(&priv.PublicKey)
	if err != nil || id != hex.EncodeToString(sum[:]) {
		t.Fatalf("KeyID = %s, %v", id, err)
	}
}

// TestLogKeyVerifiersOpenRekorStyleNotes: a good note opens with one verified
// signature; a flipped signature byte under the right key hash is
// *note.InvalidSignatureError; another key is *note.UnverifiedNoteError; a
// cosignature by an unknown key is absorbed into UnverifiedSigs; and the name
// on the line is a tautology — the same key verifies whatever the line calls
// itself.
func TestLogKeyVerifiersOpenRekorStyleNotes(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	text := "rekor.example - 1193050959916656506\n42\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"
	vs, err := NewLogKeyVerifiers(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	n, err := note.Open(signNote(t, priv, "rekor.example", text), vs)
	if err != nil || n.Text != text || len(n.Sigs) != 1 || n.Sigs[0].Name != "rekor.example" {
		t.Fatalf("good note: %+v, %v", n, err)
	}

	var bad *note.InvalidSignatureError
	if _, err := note.Open(flipSignature(t, signNote(t, priv, "rekor.example", text)), vs); !errors.As(err, &bad) {
		t.Fatalf("flipped signature: err = %v, want *note.InvalidSignatureError", err)
	}

	var unverified *note.UnverifiedNoteError
	if _, err := note.Open(signNote(t, other, "rekor.example", text), vs); !errors.As(err, &unverified) {
		t.Fatalf("other key: err = %v, want *note.UnverifiedNoteError", err)
	}

	cosigned := append(signNote(t, priv, "rekor.example", text), signNote(t, other, "witness.example", text)[len(text)+1:]...)
	n, err = note.Open(cosigned, vs)
	if err != nil || len(n.Sigs) != 1 || len(n.UnverifiedSigs) != 1 || n.UnverifiedSigs[0].Name != "witness.example" {
		t.Fatalf("cosigned: %+v, %v", n, err)
	}

	if n, err := note.Open(signNote(t, priv, "elsewhere", text), vs); err != nil || n.Sigs[0].Name != "elsewhere" {
		t.Fatalf("the line's name is not judged: %+v, %v", n, err)
	}
}

// TestParseLogKeyIsECDSAP256Only: PKIX PEM on P-256 parses; Ed25519, RSA and
// P-384 are refused by name; a non-PEM or a PRIVATE KEY block is refused.
func TestParseLogKeyIsECDSAP256Only(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if pub, err := ParseLogKey(pemPKIX(t, &p256.PublicKey)); err != nil || !pub.Equal(&p256.PublicKey) {
		t.Fatalf("P-256: %v", err)
	}
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	for name, c := range map[string]struct {
		in   []byte
		want string
	}{
		"ed25519": {pemPKIX(t, edPub), "key is Ed25519; a transparency log's checkpoint key must be ECDSA"},
		"rsa":     {pemPKIX(t, &rsaKey.PublicKey), "key is RSA; a transparency log's checkpoint key must be ECDSA"},
		"p384":    {pemPKIX(t, &p384.PublicKey), "key is ECDSA on curve P-384; want P-256"},
		"not pem": {[]byte("hello"), "not a PEM PUBLIC KEY block"},
		"private": {pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}}), "not a PEM PUBLIC KEY block"},
	} {
		_, err := ParseLogKey(c.in)
		if err == nil || err.Error() != c.want {
			t.Fatalf("%s: err = %v, want %q", name, err, c.want)
		}
	}
}

// TestLeafHashIsRFC6962: sha256(0x00 ‖ body), the value Rekor uses as an
// entry's UUID — pinned against an independent computation so the library's
// leaf prefix is a tested fact, not a remembered one.
func TestLeafHashIsRFC6962(t *testing.T) {
	body := []byte(`{"apiVersion":"0.0.1","kind":"hashedrekord"}`)
	want := sha256.Sum256(append([]byte{0x00}, body...))
	if got := leafHash(body); hex.EncodeToString(got) != hex.EncodeToString(want[:]) {
		t.Fatalf("leafHash = %x, want %x", got, want)
	}
	if !strings.HasPrefix(hex.EncodeToString(leafHash(nil)), "6e340b9cffb37a989ca544e6bb780a2c") {
		t.Fatal("leafHash(nil) must be sha256(0x00)")
	}
}
