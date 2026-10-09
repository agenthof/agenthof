package config

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"time"
)

// SignatureFormatV1 is the first line of the operator-signature payload and
// of the installed/<hex>.sig file: domain separation plus the format
// version. The payload is a wire contract of the same class as files/v1
// (hash.go): an independent implementation reproduces it byte for byte,
// and a change to it is a new format string, never an edit of this one.
const SignatureFormatV1 = "agenthof-config-signature/v1"

// logIDRE is the control ledger's genesis log_id: 16 bytes, lowercase hex.
// keyIDRE is a signing key's id: SHA-256 of the raw public key, lowercase
// hex, no prefix (a "sha256:" prefix would read like a configuration hash).
var (
	logIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)
	keyIDRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// KeyID identifies an Ed25519 public key: lowercase hex of SHA-256 over the
// raw 32-byte key — never the PEM, never the DER. An execution point
// computes it from its pinned key the same way, so a signature by another
// key reads "unknown key" instead of "bad signature".
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// SignaturePayload is the signed statement about one install, canon
// agenthof-config-signature/v1: six lines, each terminated by a single
// "\n", no carriage return, no whitespace around a value, nothing else —
// the format line; "hash: " and the installed pointer verbatim; "log_id: "
// and the control ledger's genesis log_id; "version: " and the installing
// event's seq as the shortest decimal (never 07, +7 or 7.0); "installed_at: "
// and that event's time as RFC 3339 UTC (RFC3339Nano: trailing zeros of the
// fraction stripped, no fraction when zero, the zone the literal Z); and
// "key_id: " and the signing key's id. at must already be UTC: the caller
// normalizes the ledger's time ONCE and serves that same value, so the
// served installed_at string and the signed line are one rendering by
// construction (encoding/json renders a UTC time.Time with exactly
// RFC3339Nano). A zoned time is refused, never re-rendered here. Every
// other input is checked against its grammar: a malformed value is an
// error, never a payload.
func SignaturePayload(hash, logID string, version int, at time.Time, keyID string) ([]byte, error) {
	switch {
	case !installedHashRE.MatchString(hash):
		return nil, fmt.Errorf("signature payload: malformed hash %q", hash)
	case !logIDRE.MatchString(logID):
		return nil, fmt.Errorf("signature payload: malformed log_id %q", logID)
	case version < 1:
		return nil, fmt.Errorf("signature payload: version %d is not a ledger seq", version)
	case at.Location() != time.UTC:
		return nil, fmt.Errorf("signature payload: installed_at must be UTC, got zone %s", at.Location())
	case !keyIDRE.MatchString(keyID):
		return nil, fmt.Errorf("signature payload: malformed key_id %q", keyID)
	}
	return []byte(SignatureFormatV1 + "\n" +
		"hash: " + hash + "\n" +
		"log_id: " + logID + "\n" +
		"version: " + strconv.Itoa(version) + "\n" +
		"installed_at: " + at.Format(time.RFC3339Nano) + "\n" +
		"key_id: " + keyID + "\n"), nil
}

// Sign is pure Ed25519 (RFC 8032: no prehash, no context beyond the
// payload's own first line) over the whole payload. The result is standard
// base64 with padding — 88 characters, no line breaks — the form carried
// on the wire and in the .sig file.
func Sign(priv ed25519.PrivateKey, payload []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))
}

// Verify checks sig, as Sign encodes it, over payload under pub. A string
// that is not base64 of exactly 64 bytes verifies as false.
func Verify(pub ed25519.PublicKey, payload []byte, sig string) bool {
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, payload, raw)
}
