package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyRejectsRoleWithNoAccessFloor(t *testing.T) {
	root := writeSample(t) // valid config (software-engineer is ["*"])
	// overwrite the role to remove its access floor
	rolePath := filepath.Join(root, "roles", "se.yaml")
	if err := os.WriteFile(rolePath, []byte("name: software-engineer\nworkflows: [fix-bug]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	controlLog := filepath.Join(t.TempDir(), "control.jsonl")
	var out bytes.Buffer
	if code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--as", "dana@example.com"}, &out); code != 1 {
		t.Fatalf("apply should fail for a role with no access floor; code=%d out=%s", code, out.String())
	}
	// ValidationError.Error() (internal/registry/validate.go) prints the
	// human message, not the machine code, so assert on the role name and
	// a keyword from the "no-access-floor" message — mirroring how the
	// sibling TestApplyFailsOnFrontedAgentMissingEndpoint above asserts on
	// the agent name and "endpoint" rather than a bad-execution/-endpoint
	// code.
	if !strings.Contains(out.String(), "software-engineer") {
		t.Fatalf("expected the role name in output, got %s", out.String())
	}
	if !strings.Contains(out.String(), "allowed_groups") {
		t.Fatalf("expected the missing-access-floor message in output, got %s", out.String())
	}
}
