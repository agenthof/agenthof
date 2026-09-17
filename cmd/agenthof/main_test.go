package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
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

func TestRunAndAuditEndToEnd(t *testing.T) {
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
	for _, want := range []string{"invoked by dana@example.com (asserted", "status: succeeded", "step plan succeeded"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("audit missing %q:\n%s", want, out.String())
		}
	}
}

func TestRunFailBackOffline(t *testing.T) {
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
	root := writeSample(t)
	var out bytes.Buffer
	code := cmdRun([]string{"ghost", "fix-bug", "--input", "x", "--as", "dev@x",
		"--config", root, "--log-dir", t.TempDir()}, &out)
	if code == 0 || !strings.Contains(out.String(), "refused") {
		t.Fatalf("code=%d out=%s", code, out.String())
	}
}
