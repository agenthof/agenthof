package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/ledger"
)

func TestInstalledStoreIsBesideTheControlLog(t *testing.T) {
	if got := installedStore(".agenthof/control.jsonl"); got != filepath.Join(".agenthof", "installed") {
		t.Fatalf("got %q", got)
	}
	if got := installedStore("control.jsonl"); got != "installed" {
		t.Fatalf("got %q", got)
	}
	if got := installedStore("/var/lib/agenthof/ctl/control.jsonl"); got != "/var/lib/agenthof/ctl/installed" {
		t.Fatalf("got %q", got)
	}
}

func TestApplyFloorErrors(t *testing.T) {
	ok := config.Config{Roles: []config.RoleDef{
		{Name: "se", Workflows: []string{"w"}, AllowedGroups: []string{"*"}},
		{Name: "ops", AllowedGroups: []string{"platform-eng"}, Control: []string{"enable", "apply"}},
	}}
	if errs := applyFloorErrors(ok); len(errs) != 0 {
		t.Fatalf("a config granting apply must pass: %v", errs)
	}
	bad := config.Config{Roles: []config.RoleDef{
		{Name: "se", Workflows: []string{"w"}, AllowedGroups: []string{"*"}},
		{Name: "ops", AllowedGroups: []string{"platform-eng"}, Control: []string{"enable", "disable", "repair"}},
	}}
	errs := applyFloorErrors(bad)
	if len(errs) != 1 || errs[0].Code != "no-apply-floor" {
		t.Fatalf("want one no-apply-floor error, got %+v", errs)
	}
	if got := errs[0].Error(); got != "roles: (config): no role grants apply: a configuration nobody may apply could never be changed again; grant control: [apply] to at least one role" {
		t.Fatalf("message = %q", got)
	}
	if errs := applyFloorErrors(config.Config{}); len(errs) != 1 {
		t.Fatalf("an empty config grants apply to nobody: %+v", errs)
	}
}

// pointerFixture writes a control ledger with the given successful-apply
// hashes (plus one disable record carrying a different hash, which must never
// count) and a pointer naming current; it returns the ledger path and the
// verified records.
func pointerFixture(t *testing.T, applied []string, current string) (string, []ledger.Record) {
	t.Helper()
	dir := t.TempDir()
	controlLog := filepath.Join(dir, "control.jsonl")
	inv := identity.Static("dana@example.com")
	for _, h := range applied {
		if _, err := control.Append(controlLog, control.Event{Action: "apply", Outcome: "success", Invoker: inv, Witness: control.CaptureWitness(), ConfigHash: h}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := control.Append(controlLog, control.Event{Action: "disable", Agent: "coder", Outcome: "success", Invoker: inv, Witness: control.CaptureWitness(),
		ConfigHash: "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}); err != nil {
		t.Fatal(err)
	}
	if current != "" {
		if err := os.MkdirAll(installedStore(controlLog), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(installedStore(controlLog), config.InstalledPointer), []byte(current), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	recs, _, err := ledger.ReadVerify(controlLog, ledger.Locked)
	if err != nil {
		t.Fatal(err)
	}
	return controlLog, recs
}

func TestInstalledPointerLine(t *testing.T) {
	const a = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const b = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	controlLog, recs := pointerFixture(t, []string{a, b}, b+"\n")
	if line, mismatch := installedPointerLine(controlLog, recs); mismatch || line != "installed config: "+b+" — matches the last recorded apply\n" {
		t.Fatalf("match case: mismatch=%v line=%q", mismatch, line)
	}

	controlLog, recs = pointerFixture(t, []string{b, a}, b+"\n")
	line, mismatch := installedPointerLine(controlLog, recs)
	if !mismatch || line != "installed config: "+b+" — does NOT match the last recorded apply ("+a+"): the install was not recorded, or its record was lost\n" {
		t.Fatalf("older-apply case must compare against the LAST apply: mismatch=%v line=%q", mismatch, line)
	}

	controlLog, recs = pointerFixture(t, nil, a+"\n")
	if line, mismatch := installedPointerLine(controlLog, recs); !mismatch || !strings.Contains(line, "no successful apply on record") {
		t.Fatalf("no-apply case: mismatch=%v line=%q", mismatch, line)
	}

	controlLog, recs = pointerFixture(t, []string{a}, "")
	if line, mismatch := installedPointerLine(controlLog, recs); mismatch || line != "" {
		t.Fatalf("no store: must print nothing: mismatch=%v line=%q", mismatch, line)
	}

	controlLog, recs = pointerFixture(t, []string{a}, "garbage\n")
	if line, mismatch := installedPointerLine(controlLog, recs); !mismatch || !strings.HasPrefix(line, "installed config: ") || !strings.Contains(line, "malformed pointer") {
		t.Fatalf("malformed pointer: mismatch=%v line=%q", mismatch, line)
	}
}
