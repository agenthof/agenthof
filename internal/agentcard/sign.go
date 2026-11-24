package agentcard

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// Sign returns cardJSON with a "signatures" member holding one detached-JWS
// signature (alg EdDSA, the given kid) over the JCS-canonical card body with
// "signatures" removed: the exact content Verify checks. Any existing
// signatures are replaced. The card is re-marshaled (compact, keys sorted), so
// the output is not byte-preserving. Input Parse would refuse (duplicate keys,
// trailing data) and an empty kid are refused.
func Sign(cardJSON []byte, kid string, priv ed25519.PrivateKey) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("sign agent card: private key is %d bytes, want %d", len(priv), ed25519.PrivateKeySize)
	}
	if kid == "" {
		return nil, errors.New("sign agent card: kid is empty")
	}
	if err := rejectDuplicateKeys(cardJSON); err != nil {
		return nil, fmt.Errorf("sign agent card: %w", err)
	}
	body, err := signedBody(cardJSON)
	if err != nil {
		return nil, fmt.Errorf("sign agent card: %w", err)
	}
	var m map[string]any
	if err := decodeUseNumber(cardJSON, &m); err != nil {
		return nil, fmt.Errorf("sign agent card: %w", err)
	}
	if m == nil {
		return nil, errors.New("sign agent card: card is not a JSON object")
	}
	enc := base64.RawURLEncoding
	hdr, err := json.Marshal(map[string]string{"alg": signatureAlg, "kid": kid})
	if err != nil {
		return nil, fmt.Errorf("sign agent card: %w", err)
	}
	p := enc.EncodeToString(hdr)
	sig := ed25519.Sign(priv, []byte(p+"."+enc.EncodeToString(body)))
	m["signatures"] = []map[string]string{{"protected": p, "signature": enc.EncodeToString(sig)}}
	var out bytes.Buffer
	e := json.NewEncoder(&out)
	e.SetEscapeHTML(false)
	if err := e.Encode(m); err != nil {
		return nil, fmt.Errorf("sign agent card: %w", err)
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), nil
}
