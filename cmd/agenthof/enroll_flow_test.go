package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

func TestEnrollWritesEmbeddingModel(t *testing.T) {
	gw := "models:\n  fast: {endpoint: http://localhost:4000, model: fast, api_key_env: K}\n" +
		"  embed: {endpoint: http://localhost:4000, model: embed, api_key_env: K}\n" +
		"tools:\n  code-search: {kind: mcp, url: https://mcp.example.internal/cs, credential_source: static_env, token_env: T, read_only_tools: [search]}\n"
	enroll := func(t *testing.T, extra map[string]any) string {
		t.Helper()
		e := newEnrollEnv(t, true)
		if err := os.WriteFile(filepath.Join(e.cfg, "gateway.yaml"), []byte(gw+"trusted_signers:\n  - {kid: curator, key: "+base64.StdEncoding.EncodeToString(e.priv.Public().(ed25519.PublicKey))+"}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		var applied bytes.Buffer
		if code := cmdApply([]string{"--config", e.cfg, "--control-log", e.log, "--as", "ops-user", "--groups", "ops"}, &applied); code != 0 {
			t.Fatalf("apply gateway: %d %s", code, applied.String())
		}
		params := map[string]any{
			"artifact":  e.art,
			"interface": "a2a",
			"model":     "fast",
			"tools":     []any{map[string]any{"resource": "code-search", "tools": []string{"search"}, "mode": "read-only"}},
		}
		for k, v := range extra {
			params[k] = v
		}
		if err := os.WriteFile(e.card, signedCardParams(t, "curator", e.priv, params), 0o600); err != nil {
			t.Fatal(err)
		}
		code, stdout, stderr := e.run(opsFlags...)
		if code != 0 {
			t.Fatalf("inspect: code=%d stderr=%s", code, stderr)
		}
		digest := takeDigest(t, stdout)
		if extra["embedding"] != nil && !strings.Contains(stdout, "embedding model embed") {
			t.Fatalf("disclosure lacks the embedding grant:\n%s", stdout)
		}
		if code, _, stderr := e.run(append(opsFlags, "--accept", digest)...); code != 0 {
			t.Fatalf("accept: code=%d stderr=%s", code, stderr)
		}
		b, err := os.ReadFile(filepath.Join(e.cfg, "agents", "triage.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if code := cmdApply([]string{"--config", e.cfg, "--control-log", e.log, "--as", "ops-user", "--groups", "ops"}, &out); code != 0 {
			t.Fatalf("apply after enroll: %d %s", code, out.String())
		}
		return string(b)
	}
	if got := enroll(t, map[string]any{"embedding": "embed"}); !strings.Contains(got, "embedding_model: embed\n") {
		t.Fatalf("agent file lacks the embedding grant:\n%s", got)
	}
	if got := enroll(t, nil); strings.Contains(got, "embedding_model") {
		t.Fatalf("agent file holds an embedding grant nobody requested:\n%s", got)
	}
}
