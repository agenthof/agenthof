package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
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
