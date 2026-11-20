package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// signedCard builds a card whose canonical (JCS) form is plain compact JSON
// with sorted keys, signs it with priv under kid, and returns the file bytes.
func signedCard(t *testing.T, kid string, priv ed25519.PrivateKey, artifact string) []byte {
	t.Helper()
	body := map[string]any{
		"name":    "Triage Bot",
		"version": "1.2.0",
		"capabilities": map[string]any{"extensions": []any{map[string]any{
			"uri": "https://agenthof.dev/ext/agent/v1",
			"params": map[string]any{
				"artifact":  artifact,
				"interface": "a2a",
				"model":     "fast",
				"tools":     []any{map[string]any{"resource": "code-search", "tools": []string{"search"}, "mode": "read-only"}},
			},
		}}},
	}
	canon, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding
	ph, _ := json.Marshal(map[string]any{"alg": "EdDSA", "kid": kid})
	p := enc.EncodeToString(ph)
	sig := ed25519.Sign(priv, []byte(p+"."+enc.EncodeToString(canon)))
	body["signatures"] = []any{map[string]any{"protected": p, "signature": enc.EncodeToString(sig)}}
	out, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
