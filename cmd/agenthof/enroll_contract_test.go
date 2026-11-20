package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/agentcard"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/ledger"
)

// enrollEnv is an installed configuration with one trusted curator key, an
// "ops" group allowed to apply and enroll, and a "dev" role to inherit from.
type enrollEnv struct {
	cfg, log, card string
	priv           ed25519.PrivateKey
	art            string
}

func newEnrollEnv(t *testing.T, signers bool) *enrollEnv {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	e := &enrollEnv{
		cfg:  filepath.Join(root, "config"),
		log:  filepath.Join(root, "ctl", "control.jsonl"),
		card: filepath.Join(root, "card.json"),
		priv: priv,
		art:  "ghcr.io/acme/triage@sha256:" + strings.Repeat("a", 64),
	}
	gw := "models:\n  fast: {endpoint: http://localhost:4000, model: fast, api_key_env: K}\n" +
		"tools:\n  code-search: {kind: mcp, url: https://mcp.example.internal/cs, credential_source: static_env, token_env: T, read_only_tools: [search]}\n"
	if signers {
		gw += "trusted_signers:\n  - {kid: curator, key: " + base64.StdEncoding.EncodeToString(pub) + "}\n"
	}
	writeTree(t, e.cfg, map[string]string{
		"gateway.yaml":        gw,
		"agents/orch.yaml":    "name: orch\nendpoint: http://localhost:9\n",
		"workflows/main.yaml": "name: main\nsteps:\n  - {name: s, agent: orch}\n",
		"roles/admin.yaml":    "name: admin\nworkflows: [main]\nallowed_groups: [ops]\ncontrol: [apply, enroll]\n",
		"roles/dev.yaml":      "name: dev\nworkflows: [main]\nallowed_groups: [devs]\n",
	})
	var out bytes.Buffer
	if code := cmdApply([]string{"--config", e.cfg, "--control-log", e.log, "--as", "ops-user", "--groups", "ops"}, &out); code != 0 {
		t.Fatalf("apply: %d %s", code, out.String())
	}
	e.writeCard(t, priv)
	return e
}

func (e *enrollEnv) writeCard(t *testing.T, key ed25519.PrivateKey) []byte {
	t.Helper()
	b := signedCard(t, "curator", key, e.art)
	if err := os.WriteFile(e.card, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return b
}

func (e *enrollEnv) run(extra ...string) (int, string, string) {
	var o, er bytes.Buffer
	args := append([]string{e.card, "--name", "triage", "--role", "dev", "--config", e.cfg, "--control-log", e.log}, extra...)
	return cmdEnroll(args, &o, &er), o.String(), er.String()
}

func (e *enrollEnv) events(t *testing.T) []control.DecodedEvent {
	t.Helper()
	v, err := control.Read(e.log, 0)
	if err != nil {
		t.Fatal(err)
	}
	var evs []control.DecodedEvent
	for _, r := range v.Records {
		d, err := control.Decode(r.Raw)
		if err != nil {
			t.Fatal(err)
		}
		evs = append(evs, d)
	}
	return evs
}

func (e *enrollEnv) last(t *testing.T) control.DecodedEvent {
	t.Helper()
	evs := e.events(t)
	return evs[len(evs)-1]
}

func (e *enrollEnv) hash(t *testing.T) string {
	t.Helper()
	h, err := config.HashDir(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

var opsFlags = []string{"--as", "ops-user", "--groups", "ops"}

func TestEnrollFlow(t *testing.T) {
	e := newEnrollEnv(t, true)
	before, n := e.hash(t), len(e.events(t))

	// Not authorized: refused, recorded with the target and a fixed reason.
	if code, _, _ := e.run("--as", "dev-user", "--groups", "devs"); code != 1 || e.hash(t) != before {
		t.Fatalf("unauthorized invoker: code=%d", code)
	}
	ev := e.last(t)
	if len(e.events(t)) != n+1 || ev.Action != "enroll" || ev.Outcome != "refused" || ev.Agent != "triage" ||
		ev.Reason == nil || ev.Reason.Code != control.CodeNotAuthorized || ev.Reason.Message != control.NotAuthorized("enroll").Message {
		t.Fatalf("not_authorized record = %+v", ev)
	}

	// Inspect only: disclosure, nothing written, nothing recorded.
	n = len(e.events(t))
	code, stdout, stderr := e.run(opsFlags...)
	if code != 0 || e.hash(t) != before || len(e.events(t)) != n {
		t.Fatalf("inspect: code=%d stderr=%s", code, stderr)
	}
	digest := takeDigest(t, stdout)
	if !strings.Contains(stdout, e.art) || !strings.Contains(stdout, "provenance:") {
		t.Fatalf("disclosure lacks the artifact or the provenance block:\n%s", stdout)
	}

	// A wrong digest: declined, recorded with the fixed reason, payload and target.
	n = len(e.events(t))
	if code, _, _ := e.run(append(opsFlags, "--accept", "sha256:"+strings.Repeat("0", 64))...); code != 1 || e.hash(t) != before {
		t.Fatalf("wrong digest: code=%d", code)
	}
	ev = e.last(t)
	if len(e.events(t)) != n+1 || ev.Agent != "triage" || ev.Outcome != "refused" || ev.Reason == nil ||
		ev.Reason.Code != control.CodeConsentDeclined || ev.Reason.Message != msgEnrollDeclined ||
		ev.Enroll == nil || ev.Enroll.CardSHA256 != strings.TrimPrefix(digest, "sha256:") || ev.Enroll.SignerKID != "curator" {
		t.Fatalf("consent_declined record = %+v", ev)
	}

	// An untrusted signature: hard refusal, fixed reason, no payload.
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	e.writeCard(t, otherPriv)
	n = len(e.events(t))
	if code, _, _ := e.run(append(opsFlags, "--accept", digest)...); code != 1 || e.hash(t) != before {
		t.Fatalf("untrusted signature: code=%d", code)
	}
	ev = e.last(t)
	if len(e.events(t)) != n+1 || ev.Agent != "triage" || ev.Outcome != "refused" || ev.Enroll != nil || ev.Reason == nil ||
		ev.Reason.Code != control.CodeSignatureFailure || ev.Reason.Message != msgEnrollSignature {
		t.Fatalf("signature_failure record = %+v", ev)
	}
	raw := e.writeCard(t, e.priv)

	// The right digest: three files, one recorded success carrying the whole contract.
	n = len(e.events(t))
	code, stdout, stderr = e.run(append(opsFlags, "--accept", digest)...)
	if code != 0 {
		t.Fatalf("accept: code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if len(e.events(t)) != n+1 {
		t.Fatalf("enroll success not recorded once")
	}
	card, err := agentcard.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	ev = e.last(t)
	if ev.Action != "enroll" || ev.Outcome != "success" || ev.Agent != "triage" || ev.ConfigHash != "" || ev.Enroll == nil {
		t.Fatalf("success record = %+v", ev)
	}
	p := ev.Enroll
	if p.CardSHA256 != card.SignedDigest() || "sha256:"+p.CardSHA256 != digest || p.SignerKID != "curator" || p.Artifact != e.art || len(p.Requested) == 0 {
		t.Fatalf("success payload = %+v", p)
	}
	if len(p.Files) != 3 {
		t.Fatalf("files = %+v", p.Files)
	}
	for _, f := range p.Files {
		b, err := os.ReadFile(filepath.Join(e.cfg, filepath.FromSlash(f.Path)))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != f.SHA256 {
			t.Errorf("%s: recorded sha256 %s is not the file's", f.Path, f.SHA256)
		}
	}
	if p.Files[len(p.Files)-1].Path != "agents/triage.yaml" {
		t.Errorf("the agent file must be written last: %+v", p.Files)
	}
	// The written agent grants no spawn, endpoint or exec, and carries provenance.
	agentYAML, _ := os.ReadFile(filepath.Join(e.cfg, "agents", "triage.yaml"))
	for _, bad := range []string{"may_spawn", "endpoint", "exec"} {
		if strings.Contains(string(agentYAML), bad) {
			t.Errorf("agent file holds %q:\n%s", bad, agentYAML)
		}
	}
	if !strings.Contains(string(agentYAML), "card_sha256: "+card.SignedDigest()) {
		t.Errorf("agent provenance lacks the signed digest:\n%s", agentYAML)
	}
	for _, want := range []string{"may_spawn:", `role: "triage"`, "images:"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("handoff lacks %q:\n%s", want, stdout)
		}
	}
	var out bytes.Buffer
	if code := cmdApply([]string{"--config", e.cfg, "--control-log", e.log, "--as", "ops-user", "--groups", "ops"}, &out); code != 0 {
		t.Fatalf("apply after enroll: %d %s", code, out.String())
	}

	// Re-enrolling the same name is refused.
	if code, _, _ := e.run(append(opsFlags, "--accept", digest)...); code != 1 {
		t.Fatalf("name reuse accepted: code=%d", code)
	}
}

func TestEnrollRefusesWithoutSigners(t *testing.T) {
	e := newEnrollEnv(t, false)
	before, n := e.hash(t), len(e.events(t))
	code, _, stderr := e.run(opsFlags...)
	if code != 1 || !strings.Contains(stderr, "trusted_signers") || e.hash(t) != before || len(e.events(t)) != n {
		t.Fatalf("no signers: code=%d stderr=%s", code, stderr)
	}
}

func TestEnrollRefusesUninstalledRole(t *testing.T) {
	e := newEnrollEnv(t, true)
	before := e.hash(t)
	var o, er bytes.Buffer
	code := cmdEnroll(append([]string{e.card, "--name", "triage", "--role", "ghost", "--config", e.cfg, "--control-log", e.log}, opsFlags...), &o, &er)
	if code != 1 || !strings.Contains(er.String(), "not an installed role") || e.hash(t) != before {
		t.Fatalf("uninstalled role: code=%d stderr=%s", code, er.String())
	}
}

func TestEnrollRollsBackWhenRecordFails(t *testing.T) {
	e := newEnrollEnv(t, true)
	before := e.hash(t)
	_, stdout, _ := e.run(opsFlags...)
	digest := takeDigest(t, stdout)

	orig := enrollAppend
	enrollAppend = func(string, control.Event) (ledger.Head, error) { return ledger.Head{}, errors.New("disk full") }
	defer func() { enrollAppend = orig }()

	code, _, stderr := e.run(append(opsFlags, "--accept", digest)...)
	if code != 1 || !strings.Contains(stderr, "files were removed") {
		t.Fatalf("record failure: code=%d stderr=%s", code, stderr)
	}
	if e.hash(t) != before {
		t.Fatal("files written before the failed record were not removed")
	}
}

func TestEnrollRefusesUnsafeCardStrings(t *testing.T) {
	for name, art := range map[string]string{
		"artifact with a control byte": "ghcr.io/a\x1b[31m@sha256:" + strings.Repeat("a", 64),
		"unpinned artifact":            "ghcr.io/acme/triage:latest",
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnrollEnv(t, true)
			before := e.hash(t)
			e.art = art
			e.writeCard(t, e.priv)
			if code, stdout, _ := e.run(opsFlags...); code != 1 || e.hash(t) != before || strings.Contains(stdout, "\x1b") {
				t.Fatalf("code=%d stdout=%q", code, stdout)
			}
		})
	}

	// A version that reads as prose is refused.
	e := newEnrollEnv(t, true)
	canon := map[string]any{"name": "x", "version": "1.0); reviewed by security",
		"capabilities": map[string]any{"extensions": []any{map[string]any{"uri": "https://agenthof.dev/ext/agent/v1",
			"params": map[string]any{"artifact": e.art, "interface": "a2a"}}}}}
	body, _ := json.Marshal(canon)
	enc := base64.RawURLEncoding
	ph, _ := json.Marshal(map[string]any{"alg": "EdDSA", "kid": "curator"})
	p := enc.EncodeToString(ph)
	canon["signatures"] = []any{map[string]any{"protected": p, "signature": enc.EncodeToString(ed25519.Sign(e.priv, []byte(p+"."+enc.EncodeToString(body))))}}
	out, _ := json.Marshal(canon)
	if err := os.WriteFile(e.card, out, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := e.run(opsFlags...); code != 1 || !strings.Contains(stderr, "version") {
		t.Fatalf("prose version: code=%d stderr=%s", code, stderr)
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
