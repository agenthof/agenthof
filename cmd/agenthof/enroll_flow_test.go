package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/control"
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

func TestEnrollFlow(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	root := t.TempDir()
	cfg := filepath.Join(root, "config")
	writeTree(t, cfg, map[string]string{
		"gateway.yaml": "models:\n  fast: {endpoint: http://localhost:4000, model: fast, api_key_env: K}\n" +
			"tools:\n  code-search: {kind: mcp, url: https://mcp.example.internal/cs, credential_source: static_env, token_env: T, read_only_tools: [search]}\n" +
			"trusted_signers:\n  - {kid: curator, key: " + base64.StdEncoding.EncodeToString(pub) + "}\n",
		"agents/orch.yaml":    "name: orch\nendpoint: http://localhost:9\n",
		"workflows/main.yaml": "name: main\nsteps:\n  - {name: s, agent: orch}\n",
		"roles/admin.yaml":    "name: admin\nworkflows: [main]\nallowed_groups: [ops]\ncontrol: [apply, enroll]\n",
		"roles/dev.yaml":      "name: dev\nworkflows: [main]\nallowed_groups: [devs]\n",
	})
	log := filepath.Join(root, "ctl", "control.jsonl")
	var out bytes.Buffer
	if code := cmdApply([]string{"--config", cfg, "--control-log", log, "--as", "ops-user", "--groups", "ops"}, &out); code != 0 {
		t.Fatalf("apply: %d %s", code, out.String())
	}

	art := "ghcr.io/acme/triage@sha256:" + strings.Repeat("a", 64)
	card := filepath.Join(root, "card.json")
	if err := os.WriteFile(card, signedCard(t, "curator", priv, art), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(extra ...string) (int, string, string) {
		var o, e bytes.Buffer
		args := append([]string{card, "--name", "triage", "--role", "dev", "--config", cfg, "--control-log", log}, extra...)
		return cmdEnroll(args, &o, &e), o.String(), e.String()
	}
	ops := []string{"--as", "ops-user", "--groups", "ops"}
	snapshot := func() string {
		h, err := config.HashDir(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	records := func() int {
		v, err := control.Read(log, 0)
		if err != nil {
			t.Fatal(err)
		}
		return len(v.Records)
	}

	// Not authorized: refused, recorded, nothing written.
	before, n := snapshot(), records()
	if code, _, _ := run("--as", "dev-user", "--groups", "devs"); code != 1 || snapshot() != before || records() != n+1 {
		t.Fatalf("unauthorized invoker: code=%d", code)
	}

	// Inspect only: disclosure, nothing written, nothing recorded.
	n = records()
	code, stdout, stderr := run(ops...)
	if code != 0 || snapshot() != before || records() != n {
		t.Fatalf("inspect: code=%d stderr=%s", code, stderr)
	}
	m := takeDigest(t, stdout)
	if !strings.Contains(stdout, art) || !strings.Contains(stdout, "provenance:") {
		t.Fatalf("disclosure lacks the artifact or the provenance block:\n%s", stdout)
	}

	// A wrong digest: refused, recorded as declined, nothing written.
	n = records()
	if code, _, _ := run(append(ops, "--accept", "sha256:"+strings.Repeat("0", 64))...); code != 1 || snapshot() != before || records() != n+1 {
		t.Fatalf("wrong digest: code=%d", code)
	}

	// An untrusted signature: hard refusal, recorded, nothing written.
	if err := os.WriteFile(card, signedCard(t, "curator", otherPriv, art), 0o600); err != nil {
		t.Fatal(err)
	}
	n = records()
	if code, _, _ := run(append(ops, "--accept", m)...); code != 1 || snapshot() != before || records() != n+1 {
		t.Fatalf("untrusted signature: code=%d", code)
	}
	if err := os.WriteFile(card, signedCard(t, "curator", priv, art), 0o600); err != nil {
		t.Fatal(err)
	}

	// The right digest: three files, the enrollment recorded, the result applies.
	n = records()
	code, stdout, stderr = run(append(ops, "--accept", m)...)
	if code != 0 {
		t.Fatalf("accept: code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if records() != n+1 {
		t.Fatalf("enroll success not recorded once")
	}
	for _, f := range []string{"agents/triage.yaml", "workflows/triage.yaml", "roles/triage.yaml"} {
		if _, err := os.Stat(filepath.Join(cfg, f)); err != nil {
			t.Errorf("missing %s: %v", f, err)
		}
	}
	for _, want := range []string{"may_spawn:", "role: triage", "images:"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("handoff lacks %q:\n%s", want, stdout)
		}
	}
	out.Reset()
	if code := cmdApply([]string{"--config", cfg, "--control-log", log, "--as", "ops-user", "--groups", "ops"}, &out); code != 0 {
		t.Fatalf("apply after enroll: %d %s", code, out.String())
	}

	// Re-enrolling the same name is refused.
	if code, _, _ := run(append(ops, "--accept", m)...); code != 1 {
		t.Fatalf("name reuse accepted: code=%d", code)
	}
}

func takeDigest(t *testing.T, s string) string {
	t.Helper()
	i := strings.Index(s, "card digest: ")
	if i < 0 {
		t.Fatalf("no digest in %q", s)
	}
	f := strings.Fields(s[i+len("card digest: "):])
	if len(f) == 0 || !strings.HasPrefix(f[0], "sha256:") {
		t.Fatalf("no digest in %q", s)
	}
	return f[0]
}
