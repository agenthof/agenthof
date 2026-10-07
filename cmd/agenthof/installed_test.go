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

// fixtureEvent is one successful control record for pointerFixture.
type fixtureEvent struct {
	action, agent, hash string
	bootstrap           bool
}

// pointerFixture writes a control ledger of successful events and a pointer
// naming current (empty: no store at all); it returns the ledger path and the
// verified records.
func pointerFixture(t *testing.T, events []fixtureEvent, current string) (string, []ledger.Record) {
	t.Helper()
	dir := t.TempDir()
	controlLog := filepath.Join(dir, "control.jsonl")
	inv := identity.Static("dana@example.com")
	for _, e := range events {
		if _, err := control.Append(controlLog, control.Event{Action: e.action, Agent: e.agent, Outcome: "success", Invoker: inv,
			Witness: control.CaptureWitness(), ConfigHash: e.hash, Bootstrap: e.bootstrap}); err != nil {
			t.Fatal(err)
		}
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
	// No events means no ledger file was ever written; that is a valid
	// fixture (an installed pointer with an empty history), so treat a
	// missing ledger as zero records rather than a fatal.
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return controlLog, recs
}

// TestInstalledPointerLine: the pointer is compared with the LAST event
// control.Installing accepts — an apply, or a flip not marked bootstrap.
func TestInstalledPointerLine(t *testing.T) {
	const a = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const b = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const d = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	const x = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	apply := func(h string) fixtureEvent { return fixtureEvent{action: "apply", hash: h} }
	disable := func(h string) fixtureEvent { return fixtureEvent{action: "disable", agent: "coder", hash: h} }
	bootFlip := func(h string) fixtureEvent {
		return fixtureEvent{action: "enable", agent: "coder", hash: h, bootstrap: true}
	}
	mismatchTail := ": the install was not recorded, or its record was lost\n"

	cases := []struct {
		name     string
		events   []fixtureEvent
		current  string
		line     string
		mismatch bool
	}{
		{"last apply matches", []fixtureEvent{apply(a), apply(b)}, b + "\n",
			"installed config: " + b + " — matches the last recorded install (apply)\n", false},
		{"older apply does not count", []fixtureEvent{apply(b), apply(a)}, b + "\n",
			"installed config: " + b + " — does NOT match the last recorded install (" + a + ", apply)" + mismatchTail, true},
		{"flip install matches", []fixtureEvent{apply(a), disable(d)}, d + "\n",
			"installed config: " + d + " — matches the last recorded install (disable agent coder)\n", false},
		{"flip install→record gap", []fixtureEvent{apply(a)}, d + "\n",
			"installed config: " + d + " — does NOT match the last recorded install (" + a + ", apply)" + mismatchTail, true},
		{"apply install→record gap after a flip", []fixtureEvent{apply(a), disable(d)}, a + "\n",
			"installed config: " + a + " — does NOT match the last recorded install (" + d + ", disable agent coder)" + mismatchTail, true},
		{"bootstrap-era flip never vouches", []fixtureEvent{bootFlip(x)}, x + "\n",
			"installed config: " + x + " — no install on record" + mismatchTail, true},
		{"bootstrap-era flip after rm current", []fixtureEvent{apply(a), bootFlip(x)}, x + "\n",
			"installed config: " + x + " — does NOT match the last recorded install (" + a + ", apply)" + mismatchTail, true},
		{"idempotent flip", []fixtureEvent{apply(a), disable(d), disable(d)}, d + "\n",
			"installed config: " + d + " — matches the last recorded install (disable agent coder)\n", false},
		{"pre-R1.4 flip after an install (upgrade wrinkle: exit 5 until the next apply)", []fixtureEvent{apply(a), disable(x)}, a + "\n",
			"installed config: " + a + " — does NOT match the last recorded install (" + x + ", disable agent coder)" + mismatchTail, true},
		{"no events", nil, a + "\n",
			"installed config: " + a + " — no install on record" + mismatchTail, true},
		{"no store prints nothing", []fixtureEvent{apply(a)}, "", "", false},
	}
	for _, c := range cases {
		controlLog, recs := pointerFixture(t, c.events, c.current)
		line, mismatch := installedPointerLine(controlLog, recs)
		if line != c.line || mismatch != c.mismatch {
			t.Errorf("%s:\n got  mismatch=%v %q\n want mismatch=%v %q", c.name, mismatch, line, c.mismatch, c.line)
		}
	}

	controlLog, recs := pointerFixture(t, []fixtureEvent{apply(a)}, "garbage\n")
	if line, mismatch := installedPointerLine(controlLog, recs); !mismatch || !strings.HasPrefix(line, "installed config: ") || !strings.Contains(line, "malformed pointer") {
		t.Fatalf("malformed pointer: mismatch=%v line=%q", mismatch, line)
	}
}
