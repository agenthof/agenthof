package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/engine"
)

func writeSample(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"agents/planner.yaml":    "name: planner\nmodel: fast\ninstruction: plan\noutput: plan\n",
		"agents/coder.yaml":      "name: coder\nmodel: fast\ninstruction: code\noutput: patch\n",
		"workflows/fix-bug.yaml": "name: fix-bug\nsteps:\n  - name: plan\n    agent: planner\n  - name: code\n    agent: coder\n    on_failure: plan\n",
		"roles/se.yaml":          "name: software-engineer\nworkflows: [fix-bug]\n",
		"gateway.yaml":           "models:\n  fast:\n    endpoint: https://example.test/v1\n    model: m\n    api_key_env: K\n",
	}
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestApplyOKAndFailure(t *testing.T) {
	root := writeSample(t)
	var out bytes.Buffer
	if code := cmdApply([]string{"--config", root}, &out); code != 0 {
		t.Fatalf("apply: %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "registry ok: 2 agents, 1 workflows, 1 roles") {
		t.Fatalf("out: %s", out.String())
	}
	// break it: disable coder, apply must fail naming fix-bug
	out.Reset()
	if code := cmdRegistry([]string{"disable", "coder", "--config", root}, &out); code != 0 {
		t.Fatalf("disable: %s", out.String())
	}
	out.Reset()
	if code := cmdApply([]string{"--config", root}, &out); code != 1 {
		t.Fatal("apply must fail with a disabled dependency")
	}
	if !strings.Contains(out.String(), "fix-bug") || !strings.Contains(out.String(), "disabled") {
		t.Fatalf("kill-switch error must name the workflow: %s", out.String())
	}
}

func TestApplyFailsOnFrontedAgentMissingEndpoint(t *testing.T) {
	root := writeSample(t)
	// Add a fronted agent without endpoint
	helperPath := filepath.Join(root, "agents", "helper.yaml")
	if err := os.WriteFile(helperPath, []byte("name: helper\nexecution: fronted\ninstruction: help\noutput: result\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if code := cmdApply([]string{"--config", root}, &out); code != 1 {
		t.Fatalf("apply must fail with fronted agent missing endpoint, got code %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "helper") {
		t.Fatalf("error must name the agent: %s", out.String())
	}
	if !strings.Contains(out.String(), "endpoint") {
		t.Fatalf("error must mention endpoint: %s", out.String())
	}
}

func TestRunAndAuditEndToEnd(t *testing.T) {
	t.Chdir(t.TempDir())
	root := writeSample(t)
	logs := t.TempDir()
	var out bytes.Buffer
	code := cmdRun([]string{"software-engineer", "fix-bug",
		"--input", "fix the login bug", "--as", "dana@example.com",
		"--config", root, "--log-dir", logs}, &out)
	if code != 0 {
		t.Fatalf("run: %d\n%s", code, out.String())
	}
	m := regexp.MustCompile(`run (r-[0-9a-f]{8}) finished: succeeded`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("out: %s", out.String())
	}
	out.Reset()
	if code := cmdAudit([]string{m[1], "--log-dir", logs}, &out); code != 0 {
		t.Fatalf("audit: %s", out.String())
	}
	for _, want := range []string{"invoked by dana@example.com (asserted", "status: succeeded", "step plan succeeded", "ledger integrity: verified"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("audit missing %q:\n%s", want, out.String())
		}
	}
}

func TestRunFailBackOffline(t *testing.T) {
	t.Chdir(t.TempDir())
	root := writeSample(t)
	logs := t.TempDir()
	var out bytes.Buffer
	code := cmdRun([]string{"software-engineer", "fix-bug",
		"--input", "do it FAIL:coder", "--as", "dev@x", "--config", root, "--log-dir", logs}, &out)
	_ = code // coder always fails on this input; bounces exhaust; run fails honestly
	if !strings.Contains(out.String(), "finished: failed") {
		t.Fatalf("out: %s", out.String())
	}
}

func TestRunRefusedUnknownRole(t *testing.T) {
	t.Chdir(t.TempDir())
	root := writeSample(t)
	var out bytes.Buffer
	code := cmdRun([]string{"ghost", "fix-bug", "--input", "x", "--as", "dev@x",
		"--config", root, "--log-dir", t.TempDir()}, &out)
	if code == 0 || !strings.Contains(out.String(), "refused") {
		t.Fatalf("code=%d out=%s", code, out.String())
	}
}

func TestRunsPruneDeletesOldRuns(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "r-old.jsonl")
	newPath := filepath.Join(dir, "r-new.jsonl")
	if err := os.WriteFile(oldPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-200 * 24 * time.Hour)
	if err := os.Chtimes(oldPath, old, old); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	code := cmdRuns([]string{"prune", "--older-than", "180d", "--log-dir", dir}, &out)
	if code != 0 {
		t.Fatalf("prune: %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "pruned 1 run(s) and 0 artifact(s)") {
		t.Fatalf("out: %s", out.String())
	}
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Fatalf("old run should be gone, err=%v", err)
	}
	if _, err := os.Stat(newPath); err != nil {
		t.Fatalf("new run should remain: %v", err)
	}
}

func TestRunsPruneAlsoPrunesArtifactStore(t *testing.T) {
	logDir := t.TempDir()
	artifactDir := t.TempDir()

	oldArtifact := filepath.Join(artifactDir, "deadbeef")
	newArtifact := filepath.Join(artifactDir, "cafef00d")
	if err := os.WriteFile(oldArtifact, []byte("stale body"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newArtifact, []byte("fresh body"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-200 * 24 * time.Hour)
	if err := os.Chtimes(oldArtifact, old, old); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	code := cmdRuns([]string{"prune", "--older-than", "180d", "--log-dir", logDir, "--artifact-dir", artifactDir}, &out)
	if code != 0 {
		t.Fatalf("prune: %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "pruned 0 run(s) and 1 artifact(s)") {
		t.Fatalf("out: %s", out.String())
	}
	if _, err := os.Stat(oldArtifact); !os.IsNotExist(err) {
		t.Fatalf("old artifact should be gone, err=%v", err)
	}
	if _, err := os.Stat(newArtifact); err != nil {
		t.Fatalf("new artifact should remain: %v", err)
	}
}

func TestRunsPruneMissingArtifactDirIsNotAnError(t *testing.T) {
	logDir := t.TempDir()
	artifactDir := filepath.Join(t.TempDir(), "does-not-exist")

	var out bytes.Buffer
	code := cmdRuns([]string{"prune", "--older-than", "180d", "--log-dir", logDir, "--artifact-dir", artifactDir}, &out)
	if code != 0 {
		t.Fatalf("prune: %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "pruned 0 run(s) and 0 artifact(s)") {
		t.Fatalf("out: %s", out.String())
	}
	if _, err := os.Stat(artifactDir); !os.IsNotExist(err) {
		t.Fatalf("a missing artifact-dir must not be created just to find nothing to prune: %v", err)
	}
}

func TestRunsPruneGarbageDuration(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	code := cmdRuns([]string{"prune", "--older-than", "abc", "--log-dir", dir}, &out)
	if code != 2 {
		t.Fatalf("expected exit 2 for garbage duration, got %d\n%s", code, out.String())
	}
}

func TestRunsPruneMissingLogDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does-not-exist")
	var out bytes.Buffer
	code := cmdRuns([]string{"prune", "--older-than", "180d", "--log-dir", dir}, &out)
	if code != 0 {
		t.Fatalf("expected exit 0 for missing log dir, got %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "pruned 0 run(s) and 0 artifact(s)") {
		t.Fatalf("out: %s", out.String())
	}
}

func TestRunsPruneNonPositiveDuration(t *testing.T) {
	// A non-positive duration would push the cutoff into the future,
	// deleting every run file. Guard against it instead.
	cases := []string{"-5d", "0d", "-3h", "0h"}
	for _, olderThan := range cases {
		t.Run(olderThan, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "r-x.jsonl")
			if err := os.WriteFile(path, []byte("{}\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			code := cmdRuns([]string{"prune", "--older-than", olderThan, "--log-dir", dir}, &out)
			if code != 2 {
				t.Fatalf("expected exit 2 for %q, got %d\n%s", olderThan, code, out.String())
			}
			if !strings.Contains(out.String(), "--older-than must be a positive duration") {
				t.Fatalf("out for %q: %s", olderThan, out.String())
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("run file should be untouched for %q: %v", olderThan, err)
			}
		})
	}
}

func TestRunsPruneLogDirIsRegularFile(t *testing.T) {
	dir := t.TempDir()
	notADir := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(notADir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	code := cmdRuns([]string{"prune", "--older-than", "180d", "--log-dir", notADir}, &out)
	if code != 1 {
		t.Fatalf("expected exit 1 when --log-dir is a regular file, got %d\n%s", code, out.String())
	}
}

func TestRunInvalidExecutorRejected(t *testing.T) {
	root := writeSample(t)
	var out bytes.Buffer
	code := cmdRun([]string{"software-engineer", "fix-bug",
		"--input", "fix the login bug", "--as", "dana@example.com",
		"--config", root, "--log-dir", t.TempDir(), "--executor", "bogus"}, &out)
	if code != 2 {
		t.Fatalf("expected exit 2 for invalid --executor, got %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "executor") {
		t.Fatalf("error must mention executor: %s", out.String())
	}
}

func TestGatewayProvisionMissingMasterKey(t *testing.T) {
	t.Setenv("LITELLM_MASTER_KEY", "")
	var out bytes.Buffer
	code := cmdGateway([]string{"provision", "--config", "./config"}, &out)
	if code != 2 {
		t.Fatalf("expected exit 2 with LITELLM_MASTER_KEY unset, got %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "LITELLM_MASTER_KEY") {
		t.Fatalf("error must name LITELLM_MASTER_KEY: %s", out.String())
	}
}

func TestGatewayProvisionEndToEnd(t *testing.T) {
	root := writeSample(t)
	// writeSample's role has no budget; add one so the provisioner acts.
	rolePath := filepath.Join(root, "roles", "se.yaml")
	if err := os.WriteFile(rolePath, []byte("name: software-engineer\nworkflows: [fix-bug]\nbudget_usd_month: 50\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/key/generate" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"key":"sk-test"}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	t.Setenv("LITELLM_MASTER_KEY", "sk-master-test")
	t.Chdir(t.TempDir())

	var out bytes.Buffer
	code := cmdGateway([]string{"provision", "--config", root, "--admin-base", srv.URL}, &out)
	if code != 0 {
		t.Fatalf("provision: %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "provisioned key for role software-engineer (budget $50)") {
		t.Fatalf("out: %s", out.String())
	}
	if _, err := os.Stat(filepath.Join(".agenthof", "keys", "software-engineer.key")); err != nil {
		t.Fatalf("key file not written under ./.agenthof/keys/: %v", err)
	}
}

func TestRunADKExecutorEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id": "resp_1",
			"object": "response",
			"created_at": 0,
			"model": "stub-model",
			"status": "completed",
			"output": [
				{
					"id": "msg_1",
					"type": "message",
					"role": "assistant",
					"status": "completed",
					"content": [
						{"type": "output_text", "text": "stub answer", "annotations": []}
					]
				}
			],
			"usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}
		}`))
	}))
	defer srv.Close()

	const envVar = "AGENTHOF_CLI_TEST_STUB_KEY"
	t.Setenv(envVar, "sk-test-stub-key")

	root := t.TempDir()
	files := map[string]string{
		"agents/planner.yaml":    "name: planner\nmodel: fast\ninstruction: plan\noutput: plan\n",
		"agents/coder.yaml":      "name: coder\nmodel: fast\ninstruction: code\noutput: patch\n",
		"workflows/fix-bug.yaml": "name: fix-bug\nsteps:\n  - name: plan\n    agent: planner\n  - name: code\n    agent: coder\n    on_failure: plan\n",
		"roles/se.yaml":          "name: software-engineer\nworkflows: [fix-bug]\n",
		"gateway.yaml":           "models:\n  fast:\n    endpoint: " + srv.URL + "\n    model: stub-model\n    api_key_env: " + envVar + "\n",
	}
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	t.Chdir(t.TempDir())
	const logs = "runs"

	var out bytes.Buffer
	code := cmdRun([]string{"software-engineer", "fix-bug",
		"--input", "fix the login bug", "--as", "dana@example.com",
		"--config", root, "--log-dir", logs, "--executor", "adk"}, &out)
	if code != 0 {
		t.Fatalf("run: %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "finished: succeeded") {
		t.Fatalf("out: %s", out.String())
	}
	if !strings.Contains(out.String(), "workspace: ") {
		t.Fatalf("run must print the chosen workspace: %s", out.String())
	}
	m := regexp.MustCompile(`run (r-[0-9a-f]{8}) finished: succeeded`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("out: %s", out.String())
	}

	out.Reset()
	if code := cmdAudit([]string{m[1], "--log-dir", logs}, &out); code != 0 {
		t.Fatalf("audit: %s", out.String())
	}
	if !regexp.MustCompile(`succeeded — artifact [0-9a-f]{8}:`).MatchString(out.String()) {
		t.Fatalf("audit missing artifact sha8 line: %s", out.String())
	}
}

// --- OIDC wiring, ledgered validation refusals, and mux dispatch ---

// cmdTestOIDCServer spins up an httptest server serving OIDC discovery and
// JWKS documents backed by the given RSA key. Mirrors the recipe in
// internal/identity/oidc_test.go (kept separate so cmd/agenthof does not
// need to export test helpers from internal/identity).
func cmdTestOIDCServer(t *testing.T, key *rsa.PrivateKey) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                srv.URL,
			"jwks_uri":                              srv.URL + "/keys",
			"authorization_endpoint":                srv.URL + "/auth",
			"token_endpoint":                        srv.URL + "/token",
			"response_types_supported":              []string{"id_token"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})

	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"kid": "test",
					"alg": "RS256",
					"use": "sig",
					"n":   n,
					"e":   "AQAB",
				},
			},
		})
	})

	return srv
}

// cmdMintToken hand-builds an RS256-signed JWT from the given claims.
func cmdMintToken(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()

	header := map[string]any{"alg": "RS256", "kid": "test", "typ": "JWT"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestRunTokenRequiresIssuerEnv(t *testing.T) {
	t.Chdir(t.TempDir())
	root := writeSample(t)
	t.Setenv("AGENTHOF_OIDC_ISSUER", "")
	var out bytes.Buffer
	code := cmdRun([]string{"software-engineer", "fix-bug",
		"--input", "x", "--token", "some-raw-jwt-value",
		"--config", root, "--log-dir", t.TempDir()}, &out)
	if code != 2 {
		t.Fatalf("expected exit 2, got %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "AGENTHOF_OIDC_ISSUER") {
		t.Fatalf("error must name AGENTHOF_OIDC_ISSUER: %s", out.String())
	}
	if strings.Contains(out.String(), "some-raw-jwt-value") {
		t.Fatalf("error must not echo the raw token: %s", out.String())
	}
}

func TestRunStaticRBAC(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("AGENTHOF_TOKEN", "") // a token exported in the ambient shell must not divert this static-path test onto OIDC
	root := writeSample(t)
	rolePath := filepath.Join(root, "roles", "se.yaml")
	if err := os.WriteFile(rolePath, []byte("name: software-engineer\nworkflows: [fix-bug]\nallowed_groups: [finance]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	logs := t.TempDir()

	var out bytes.Buffer
	code := cmdRun([]string{"software-engineer", "fix-bug",
		"--input", "fix the login bug", "--as", "dana@example.com", "--groups", "finance",
		"--config", root, "--log-dir", logs}, &out)
	if code != 0 {
		t.Fatalf("run with allowed group: %d\n%s", code, out.String())
	}

	out.Reset()
	code = cmdRun([]string{"software-engineer", "fix-bug",
		"--input", "fix the login bug", "--as", "dana@example.com", "--groups", "engineering",
		"--config", root, "--log-dir", logs}, &out)
	if code == 0 || !strings.Contains(out.String(), "refused") {
		t.Fatalf("expected refusal for wrong group: code=%d out=%s", code, out.String())
	}
	m := regexp.MustCompile(`run (r-[0-9a-f]{8}) refused`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("out must contain run id: %s", out.String())
	}
	events, err := engine.ReadLog(logs, m[1])
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}
	if len(events) != 1 || events[0].Type != "run_refused" {
		t.Fatalf("expected single run_refused event, got %+v", events)
	}
}

func TestRunValidationFailureIsLedgered(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("AGENTHOF_TOKEN", "") // a token exported in the ambient shell must not divert this static-path test onto OIDC
	root := writeSample(t)
	var discard bytes.Buffer
	if code := cmdRegistry([]string{"disable", "coder", "--config", root}, &discard); code != 0 {
		t.Fatalf("disable: %d\n%s", code, discard.String())
	}
	logs := t.TempDir()
	var out bytes.Buffer
	code := cmdRun([]string{"software-engineer", "fix-bug",
		"--input", "x", "--as", "dev@x",
		"--config", root, "--log-dir", logs}, &out)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d\n%s", code, out.String())
	}
	m := regexp.MustCompile(`run (r-[0-9a-f]{8}) refused: configuration invalid`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("out must contain run id and refusal message: %s", out.String())
	}
	events, err := engine.ReadLog(logs, m[1])
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}
	if len(events) != 1 || events[0].Type != "run_refused" {
		t.Fatalf("expected single run_refused event, got %+v", events)
	}
	if !strings.HasPrefix(events[0].Reason, "configuration invalid:") {
		t.Fatalf("reason must start with %q: %s", "configuration invalid:", events[0].Reason)
	}
}

func TestRunOIDCHappyPathEndToEnd(t *testing.T) {
	t.Chdir(t.TempDir())
	root := writeSample(t)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	srv := cmdTestOIDCServer(t, key)
	token := cmdMintToken(t, key, map[string]any{
		"iss":   srv.URL,
		"aud":   "agenthof",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"sub":   "u-123",
		"email": "dana@example.com",
	})
	t.Setenv("AGENTHOF_OIDC_ISSUER", srv.URL)
	t.Setenv("AGENTHOF_OIDC_CLIENT_ID", "agenthof") // pin: the minted token's aud is fixed to "agenthof"

	logs := t.TempDir()
	var out bytes.Buffer
	code := cmdRun([]string{"software-engineer", "fix-bug",
		"--input", "fix the login bug", "--token", token,
		"--config", root, "--log-dir", logs}, &out)
	if code != 0 {
		t.Fatalf("run: %d\n%s", code, out.String())
	}
	if strings.Contains(out.String(), token) {
		t.Fatalf("output must not echo the raw token: %s", out.String())
	}
	m := regexp.MustCompile(`run (r-[0-9a-f]{8}) finished: succeeded`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("out: %s", out.String())
	}

	out.Reset()
	if code := cmdAudit([]string{m[1], "--log-dir", logs}, &out); code != 0 {
		t.Fatalf("audit: %s", out.String())
	}
	want := fmt.Sprintf("invoked by dana@example.com (oidc, issuer %s)", srv.URL)
	if !strings.Contains(out.String(), want) {
		t.Fatalf("audit missing %q:\n%s", want, out.String())
	}
}

// TestRunBadTokenIsRejectedWithoutEcho is the CLI-layer token-non-echo
// regression test: a real OIDC issuer is configured (so the failure is a
// genuine signature-verification failure, not a missing-issuer short
// circuit), the --token is cryptographically invalid, and the assertion
// covers both a non-zero exit with a clear error AND that the raw token
// string never appears anywhere in the combined CLI output.
func TestRunBadTokenIsRejectedWithoutEcho(t *testing.T) {
	t.Chdir(t.TempDir())
	root := writeSample(t)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	srv := cmdTestOIDCServer(t, key)
	t.Setenv("AGENTHOF_OIDC_ISSUER", srv.URL)
	t.Setenv("AGENTHOF_OIDC_CLIENT_ID", "agenthof")

	// A well-formed JWT (valid header/claims, correct issuer/audience) but
	// signed with a different key than the one the issuer's JWKS publishes —
	// so verification fails on the signature, not on shape or discovery.
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	badToken := cmdMintToken(t, otherKey, map[string]any{
		"iss":   srv.URL,
		"aud":   "agenthof",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"sub":   "u-123",
		"email": "dana@example.com",
	})

	logs := t.TempDir()
	var out bytes.Buffer
	code := cmdRun([]string{"software-engineer", "fix-bug",
		"--input", "fix the login bug", "--token", badToken,
		"--config", root, "--log-dir", logs}, &out)
	if code == 0 {
		t.Fatalf("expected non-zero exit for a bad token, got 0:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "token authentication failed") {
		t.Fatalf("error must mention authentication failure: %s", out.String())
	}
	if strings.Contains(out.String(), badToken) {
		t.Fatalf("output must not echo the raw token: %s", out.String())
	}
}

func TestRunFrontedAgentEndToEnd(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("AGENTHOF_TOKEN", "") // a token exported in the ambient shell must not divert this static-path test onto OIDC
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"artifact":"front result"}`))
	}))
	defer stub.Close()

	root := t.TempDir()
	files := map[string]string{
		"agents/helper.yaml":    "name: helper\nexecution: fronted\nendpoint: " + stub.URL + "\ninstruction: help\noutput: result\n",
		"workflows/single.yaml": "name: single\nsteps:\n  - name: step1\n    agent: helper\n",
		"roles/fr.yaml":         "name: fronted-role\nworkflows: [single]\n",
	}
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	logs := t.TempDir()
	var out bytes.Buffer
	code := cmdRun([]string{"fronted-role", "single", "--input", "go", "--as", "dev@x",
		"--config", root, "--log-dir", logs}, &out)
	if code != 0 {
		t.Fatalf("run: %d\n%s", code, out.String())
	}
	m := regexp.MustCompile(`run (r-[0-9a-f]{8}) finished: succeeded`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("out: %s", out.String())
	}

	out.Reset()
	if code := cmdAudit([]string{m[1], "--log-dir", logs}, &out); code != 0 {
		t.Fatalf("audit: %s", out.String())
	}
	if !strings.Contains(out.String(), "invoked by dev@x") {
		t.Fatalf("audit missing invoker: %s", out.String())
	}

	events, err := engine.ReadLog(logs, m[1])
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Type == "step_succeeded" && e.Execution == "fronted" {
			found = true
			// The artifact must be the stub adapter's response, not an
			// echo-executor artifact — proof the mux actually routed this
			// step to the HTTP adapter rather than falling through to the
			// contained (echo) executor.
			if e.Artifact != "front result" {
				t.Fatalf("expected artifact from the fronted stub, got %q", e.Artifact)
			}
		}
	}
	if !found {
		t.Fatalf("expected step_succeeded event with Execution=fronted, got %+v", events)
	}
}
