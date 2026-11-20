package agentcard

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Anchor is a trusted signing key, identified by the kid a card signature
// names. Anchors come from operator configuration, never from the card.
type Anchor struct {
	KID string
	Key ed25519.PublicKey
}

// signatureAlg is the only accepted JWS algorithm. The allowlist is
// deliberately one entry: no "none", no HMAC.
const signatureAlg = "EdDSA"

// keyMaterialHeaders are header parameters that would let a card supply or
// point to its own verification key; a signature entry carrying one is
// skipped (never trusted), and the card verifies only if another entry does.
var keyMaterialHeaders = []string{"jku", "jwk", "x5u", "x5c"}

// Verify checks that at least one of the card's signatures is a valid
// EdDSA JWS, over the RFC 8785 canonical form of the card with its
// "signatures" member removed, made by one of the trusted anchors, and
// returns that anchor's kid. Signatures use the detached-payload JSON
// serialization: the JWS signing input is
// BASE64URL(protected) "." BASE64URL(canonical card body).
//
// It fails closed: no anchors, no signatures, or no entry that is EdDSA, by
// a trusted kid and verifying is an error. Entries that are unusable for any
// reason (disallowed alg, key-material headers, untrusted kid, bad bytes) are
// skipped, so entry order does not matter. The card must come from Parse, so
// the bytes verified are the bytes acted on.
func Verify(c *Card, anchors []Anchor) (string, error) {
	if c == nil || len(c.raw) == 0 {
		return "", errors.New("verify agent card: card was not produced by Parse")
	}
	if len(anchors) == 0 {
		return "", errors.New("verify agent card: no trust anchors configured")
	}
	if len(c.Signatures) == 0 {
		return "", errors.New("verify agent card: card carries no signature")
	}
	body, err := signedBody(c.raw)
	if err != nil {
		return "", fmt.Errorf("verify agent card: %w", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(body)

	// Any-of: each entry stands alone and an unusable one is skipped, never
	// fatal, so the unsigned signatures list cannot be reordered or padded
	// to reject a validly signed card. Keys come only from anchors, so
	// skipping an entry that carries its own key material is safe.
	for _, s := range c.Signatures {
		if kid, ok := verifyEntry(s, payload, anchors); ok {
			return kid, nil
		}
	}
	return "", errors.New("verify agent card: no signature verifies against a trusted anchor")
}

// verifyEntry reports whether one signature is an EdDSA signature by a
// trusted anchor over the payload.
func verifyEntry(s Signature, payload string, anchors []Anchor) (string, bool) {
	kid, err := checkHeaders(s)
	if err != nil {
		return "", false
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(s.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return "", false
	}
	input := []byte(s.Protected + "." + payload)
	for _, a := range anchors {
		if a.KID != kid || len(a.Key) != ed25519.PublicKeySize {
			continue
		}
		if ed25519.Verify(a.Key, input, sig) {
			return kid, true
		}
	}
	return "", false
}

// signedBody returns the JCS form of the card with the top-level
// "signatures" member removed.
func signedBody(raw []byte) ([]byte, error) {
	if err := checkJSONStrings(raw); err != nil {
		return nil, err
	}
	var m map[string]any
	if err := decodeUseNumber(raw, &m); err != nil {
		return nil, err
	}
	for k := range m {
		// encoding/json folds case when filling Card.Signatures; a
		// differently-cased member would be read as signatures yet signed as
		// body, so only the exact spelling is accepted.
		if k != "signatures" && strings.EqualFold(k, "signatures") {
			return nil, fmt.Errorf("member %q must be spelled \"signatures\"", k)
		}
	}
	delete(m, "signatures")
	return jcs(m)
}

// checkHeaders validates one signature's headers and returns its kid. Only
// the protected header is trusted for alg and kid.
func checkHeaders(s Signature) (string, error) {
	ph, err := base64.RawURLEncoding.Strict().DecodeString(s.Protected)
	if err != nil {
		return "", fmt.Errorf("protected header is not base64url: %w", err)
	}
	if err := rejectDuplicateKeys(ph); err != nil {
		return "", fmt.Errorf("protected header: %w", err)
	}
	var hdr map[string]json.RawMessage
	if err := json.Unmarshal(ph, &hdr); err != nil {
		return "", fmt.Errorf("protected header: %w", err)
	}
	if err := rejectKeyMaterial(hdr); err != nil {
		return "", err
	}
	if _, ok := hdr["crit"]; ok {
		return "", errors.New("protected header carries unsupported crit")
	}
	if b, ok := hdr["b64"]; ok && string(b) != "true" {
		return "", errors.New("protected header b64 other than true is unsupported")
	}
	var alg string
	if err := json.Unmarshal(hdr["alg"], &alg); err != nil || alg != signatureAlg {
		return "", fmt.Errorf("protected header alg must be %q", signatureAlg)
	}
	var kid string
	if err := json.Unmarshal(hdr["kid"], &kid); err != nil || kid == "" {
		return "", errors.New("protected header has no kid")
	}
	if len(s.Header) > 0 && string(s.Header) != "null" {
		var uh map[string]json.RawMessage
		if err := json.Unmarshal(s.Header, &uh); err != nil {
			return "", fmt.Errorf("unprotected header: %w", err)
		}
		if err := rejectKeyMaterial(uh); err != nil {
			return "", err
		}
	}
	return kid, nil
}

func rejectKeyMaterial(h map[string]json.RawMessage) error {
	for k := range h {
		for _, bad := range keyMaterialHeaders {
			if strings.EqualFold(k, bad) {
				return fmt.Errorf("header carries %q; keys are never taken from the card", k)
			}
		}
	}
	return nil
}

func decodeUseNumber(b []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	return dec.Decode(v)
}
