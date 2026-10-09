package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

const (
	goldenKeyPEM = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f\n-----END PRIVATE KEY-----\n"
	goldenPubPEM = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAA6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=\n-----END PUBLIC KEY-----\n"
)

// TestSigningKeyPEMRoundTrip pins the file formats to the golden pair: the
// PEM text is byte-exact, parses back to the same keys, and the public file
// is what openssl pkey -pubout would write.
func TestSigningKeyPEMRoundTrip(t *testing.T) {
	priv, pub := goldenKey(t)
	keyPEM, err := EncodeSigningKey(priv)
	if err != nil || string(keyPEM) != goldenKeyPEM {
		t.Fatalf("EncodeSigningKey: %v\n%s", err, keyPEM)
	}
	pubPEM, err := EncodeSigningPub(pub)
	if err != nil || string(pubPEM) != goldenPubPEM {
		t.Fatalf("EncodeSigningPub: %v\n%s", err, pubPEM)
	}
	gotPriv, err := ParseSigningKey(keyPEM)
	if err != nil || !gotPriv.Equal(priv) {
		t.Fatalf("ParseSigningKey: %v", err)
	}
	gotPub, err := ParseSigningPub(pubPEM)
	if err != nil || !gotPub.Equal(pub) {
		t.Fatalf("ParseSigningPub: %v", err)
	}
	if KeyID(gotPub) != goldenKeyID {
		t.Fatal("the parsed public key must have the golden key id")
	}
}

// TestSigningKeyRefusals: another algorithm, trailing data, the wrong block
// type and no block are each refused with a message that says why.
func TestSigningKeyRefusals(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	rsaDER, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	rsaKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaDER})
	rsaPubDER, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	rsaPubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rsaPubDER})

	if _, err := ParseSigningKey(rsaKeyPEM); err == nil || !strings.Contains(err.Error(), "want Ed25519") {
		t.Fatalf("RSA private key: %v", err)
	}
	if _, err := ParseSigningPub(rsaPubPEM); err == nil || !strings.Contains(err.Error(), "want Ed25519") {
		t.Fatalf("RSA public key: %v", err)
	}
	if _, err := ParseSigningKey([]byte(goldenKeyPEM + "junk\n")); err == nil || !strings.Contains(err.Error(), "trailing data") {
		t.Fatalf("trailing data after the private block: %v", err)
	}
	if _, err := ParseSigningPub([]byte(goldenPubPEM + goldenPubPEM)); err == nil || !strings.Contains(err.Error(), "trailing data") {
		t.Fatalf("a second block is trailing data: %v", err)
	}
	if _, err := ParseSigningKey([]byte(goldenPubPEM)); err == nil || !strings.Contains(err.Error(), "PEM block type") {
		t.Fatalf("a public block where a private one is wanted: %v", err)
	}
	if _, err := ParseSigningPub([]byte(goldenKeyPEM)); err == nil || !strings.Contains(err.Error(), "PEM block type") {
		t.Fatalf("a private block where a public one is wanted: %v", err)
	}
	if _, err := ParseSigningPub([]byte("not pem at all\n")); err == nil || !strings.Contains(err.Error(), "no PEM block") {
		t.Fatalf("no block: %v", err)
	}
	// A trailing newline (what pem.Encode writes) is not trailing data.
	if _, err := ParseSigningPub([]byte(goldenPubPEM + "\n")); err != nil {
		t.Fatalf("whitespace after the block is fine: %v", err)
	}
}
