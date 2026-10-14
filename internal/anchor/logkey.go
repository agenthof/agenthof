package anchor

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"
)

// ParseLogKey parses a transparency log's checkpoint-signing public key — a
// PEM "PUBLIC KEY" block holding PKIX DER — and refuses by name anything but
// ECDSA on P-256, the key type the Rekor public-good log signs with. It is
// its own parser on purpose: the operator signing key beside the ledger
// (verify.pub) is Ed25519 and must never be mistaken for a log key. The
// caller names the file.
func ParseLogKey(pemBytes []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("not a PEM PUBLIC KEY block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("key is ECDSA on curve %s; want P-256", k.Curve.Params().Name)
		}
		return k, nil
	case ed25519.PublicKey:
		return nil, errors.New("key is Ed25519; a transparency log's checkpoint key must be ECDSA")
	case *rsa.PublicKey:
		return nil, errors.New("key is RSA; a transparency log's checkpoint key must be ECDSA")
	default:
		return nil, fmt.Errorf("key is %T; a transparency log's checkpoint key must be ECDSA", pub)
	}
}

// pkixDigest is sha256 of the key's PKIX DER — the one digest both the log's
// key identity (KeyID, Rekor's logID) and the note key hash (KeyHash) are cut
// from. No name or origin is mixed in, exactly as Rekor computes both.
func pkixDigest(pub *ecdsa.PublicKey) ([32]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(der), nil
}

// KeyID is the identity a transparency log gives its key: lowercase hex
// SHA-256 of the key's PKIX DER (Rekor's logID). It is what the anchor record
// stores as backend_key_id.
func KeyID(pub *ecdsa.PublicKey) (string, error) {
	sum, err := pkixDigest(pub)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sum[:]), nil
}

// KeyHash is the sumdb-note key hash of a log key: the big-endian uint32 of
// the first four bytes of sha256(PKIX DER). A checkpoint's signature line
// carries it ahead of the signature.
func KeyHash(pub *ecdsa.PublicKey) (uint32, error) {
	sum, err := pkixDigest(pub)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(sum[:4]), nil
}

// logKeyVerifier is the note.Verifier for one Rekor checkpoint signature:
// ECDSA P-256, ASN.1 DER, over the SHA-256 of the note text — the encoding
// Rekor's own verifier expects.
type logKeyVerifier struct {
	name string
	hash uint32
	pub  *ecdsa.PublicKey
}

func (v logKeyVerifier) Name() string    { return v.name }
func (v logKeyVerifier) KeyHash() uint32 { return v.hash }
func (v logKeyVerifier) Verify(msg, sig []byte) bool {
	d := sha256.Sum256(msg)
	return ecdsa.VerifyASN1(v.pub, d[:], sig)
}

// logKeyVerifiers is a note.Verifiers for exactly one trusted key. note.Open
// looks a signature line up by (name, key hash) and then insists the verifier
// it gets back carries that same name. The name on a Rekor checkpoint is the
// log's hostname — a server flag, not a property of the key — so this set
// matches by key hash alone and lends every match the line's own name. The
// name check inside Open is therefore a tautology here, by design: the trust
// is the key hash plus the signature, exactly as Rekor's verifier treats it.
type logKeyVerifiers struct {
	hash uint32
	pub  *ecdsa.PublicKey
}

func (k logKeyVerifiers) Verifier(name string, hash uint32) (note.Verifier, error) {
	if hash != k.hash {
		return nil, &note.UnknownVerifierError{Name: name, KeyHash: hash}
	}
	return logKeyVerifier{name: name, hash: hash, pub: k.pub}, nil
}

// NewLogKeyVerifiers returns the note.Verifiers that trusts pub and nothing
// else. Lines signed by other keys (witness cosignatures) are left in
// Note.UnverifiedSigs by note.Open and do not fail the open; a note with no
// line under pub is a *note.UnverifiedNoteError; a line under pub whose
// signature fails is a *note.InvalidSignatureError.
func NewLogKeyVerifiers(pub *ecdsa.PublicKey) (note.Verifiers, error) {
	h, err := KeyHash(pub)
	if err != nil {
		return nil, err
	}
	return logKeyVerifiers{hash: h, pub: pub}, nil
}

// leafHash is the RFC 6962 leaf hash — SHA-256 over 0x00 ‖ body — the value a
// Rekor entry's UUID is, and the Merkle leaf its inclusion proof leads from.
// Consumed from the library, never hand-rolled.
func leafHash(body []byte) []byte { return rfc6962.DefaultHasher.HashLeaf(body) }
