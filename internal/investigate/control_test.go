package investigate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/identity"
)

func TestConfigJoinMatch(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.jsonl")
	inv := identity.Static("dana@example.com")
	if _, err := control.Append(p, control.Event{Action: "apply", Outcome: "success", Invoker: inv,
		Witness: control.CaptureWitness(), ConfigHash: "sha256:aaa"}); err != nil {
		t.Fatalf("append: %v", err)
	}
	ev, verdict, ok := LoadControl(p)
	if !ok || verdict != "verified" {
		t.Fatalf("verdict=%q ok=%v", verdict, ok)
	}
	line := ConfigJoin(ev, verdict, "sha256:aaa", time.Now())
	if !strings.Contains(line, "applied by dana@example.com") {
		t.Fatalf("line=%q", line)
	}
}

func TestConfigJoinMissingLog(t *testing.T) {
	ev, verdict, ok := LoadControl(filepath.Join(t.TempDir(), "nope.jsonl"))
	if ok || verdict != "missing" {
		t.Fatalf("verdict=%q ok=%v", verdict, ok)
	}
	line := ConfigJoin(ev, verdict, "sha256:x", time.Now())
	if !strings.Contains(line, "control ledger unavailable") {
		t.Fatalf("line=%q", line)
	}
}

// joinFixture appends events to a fresh control ledger and loads it.
func joinFixture(t *testing.T, events ...control.Event) []control.DecodedEvent {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.jsonl")
	inv := identity.Static("dana@example.com")
	for _, e := range events {
		e.Invoker = inv
		e.Witness = control.CaptureWitness()
		if _, err := control.Append(p, e); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	ev, verdict, ok := LoadControl(p)
	if !ok || verdict != "verified" {
		t.Fatalf("verdict=%q ok=%v", verdict, ok)
	}
	return ev
}

func TestConfigJoinNoInstallOnRecord(t *testing.T) {
	ev := joinFixture(t, control.Event{Action: "apply", Outcome: "success", ConfigHash: "sha256:other"})
	if line := ConfigJoin(ev, "verified", "sha256:aaa", time.Now()); line != "config sha256:aaa — no install on record" {
		t.Fatalf("line=%q", line)
	}
}

// TestConfigJoinFlipInstall: a run after a disable executes the flip's
// snapshot; the join names the flip as the install (form 2), with no apply
// row for that hash at all.
func TestConfigJoinFlipInstall(t *testing.T) {
	ev := joinFixture(t,
		control.Event{Action: "apply", Outcome: "success", ConfigHash: "sha256:aaa"},
		control.Event{Action: "disable", Agent: "coder", Outcome: "success", ConfigHash: "sha256:ddd"})
	line := ConfigJoin(ev, "verified", "sha256:ddd", time.Now())
	want := "config sha256:ddd — installed by dana@example.com (asserted) at " + ev[1].Time.Format(time.RFC3339) + " (kill switch: disabled agent coder)"
	if line != want {
		t.Fatalf("line=%q\nwant=%q", line, want)
	}
	ev = joinFixture(t,
		control.Event{Action: "apply", Outcome: "success", ConfigHash: "sha256:aaa"},
		control.Event{Action: "disable", Agent: "coder", Outcome: "success", ConfigHash: "sha256:ddd"},
		control.Event{Action: "enable", Agent: "coder", Outcome: "success", ConfigHash: "sha256:eee"})
	if line := ConfigJoin(ev, "verified", "sha256:eee", time.Now()); !strings.HasSuffix(line, "(kill switch: enabled agent coder)") || !strings.Contains(line, "installed by dana@example.com (asserted)") {
		t.Fatalf("line=%q", line)
	}
}

// TestConfigJoinLastInstallWins: two applies of the same bytes — the later
// one is named (ledger order, no clock comparison).
func TestConfigJoinLastInstallWins(t *testing.T) {
	ev := joinFixture(t,
		control.Event{Action: "apply", Outcome: "success", ConfigHash: "sha256:aaa"},
		control.Event{Action: "apply", Outcome: "success", ConfigHash: "sha256:aaa"})
	line := ConfigJoin(ev, "verified", "sha256:aaa", time.Now())
	if !strings.Contains(line, "applied by dana@example.com (asserted) at "+ev[1].Time.Format(time.RFC3339)) {
		t.Fatalf("line=%q", line)
	}
}

// TestConfigJoinBootstrapFlipIsNotAnInstall: a bootstrap-era flip X then a
// clean apply of the unchanged directory (hash X): the join names the apply
// (form 1), never the flip.
func TestConfigJoinBootstrapFlipIsNotAnInstall(t *testing.T) {
	ev := joinFixture(t,
		control.Event{Action: "enable", Agent: "coder", Outcome: "success", ConfigHash: "sha256:xxx", Bootstrap: true},
		control.Event{Action: "apply", Outcome: "success", ConfigHash: "sha256:xxx", Bootstrap: true})
	line := ConfigJoin(ev, "verified", "sha256:xxx", time.Now())
	if !strings.HasPrefix(line, "config sha256:xxx — applied by") || strings.Contains(line, "kill switch") {
		t.Fatalf("line=%q", line)
	}
	// The flip alone vouches for nothing.
	ev = joinFixture(t, control.Event{Action: "enable", Agent: "coder", Outcome: "success", ConfigHash: "sha256:xxx", Bootstrap: true})
	if line := ConfigJoin(ev, "verified", "sha256:xxx", time.Now()); line != "config sha256:xxx — no install on record" {
		t.Fatalf("line=%q", line)
	}
}

// TestConfigJoinLaterOnlyIsForm3: the hash matches only installing events
// AFTER the run started — a later apply, or a later flip — and the reader
// is told the hash is known but not vouched for at run time.
func TestConfigJoinLaterOnlyIsForm3(t *testing.T) {
	runStart := time.Now()
	time.Sleep(2 * time.Millisecond)
	const want = "config sha256:aaa — no install on record at the run's start (matches a later apply or kill-switch flip)"
	ev := joinFixture(t, control.Event{Action: "apply", Outcome: "success", ConfigHash: "sha256:aaa"})
	if line := ConfigJoin(ev, "verified", "sha256:aaa", runStart); line != want {
		t.Fatalf("later apply: line=%q", line)
	}
	ev = joinFixture(t, control.Event{Action: "disable", Agent: "coder", Outcome: "success", ConfigHash: "sha256:aaa"})
	if line := ConfigJoin(ev, "verified", "sha256:aaa", runStart); line != want {
		t.Fatalf("later flip: line=%q", line)
	}
}

// TestConfigJoinFailedApplyIsNotAnInstall: a non-success apply with the
// run's hash installs nothing — form 4.
func TestConfigJoinFailedApplyIsNotAnInstall(t *testing.T) {
	ev := joinFixture(t, control.Event{Action: "apply", Outcome: "rejected",
		Reason: &control.Reason{Code: control.CodeValidationFailed, Message: "bad config"}, ConfigHash: "sha256:aaa"})
	if line := ConfigJoin(ev, "verified", "sha256:aaa", time.Now()); line != "config sha256:aaa — no install on record" {
		t.Fatalf("line=%q", line)
	}
}

func TestLoadControlErrorVerdict(t *testing.T) {
	// A present-but-unreadable file: create it then strip read permission.
	// (Skipped verdict-wise if running as root, where permissions are
	// bypassed — the "error" branch is still exercised whenever this
	// process is unprivileged, which is the normal CI/dev case.)
	p := filepath.Join(t.TempDir(), "unreadable.jsonl")
	if err := os.WriteFile(p, []byte(`{"prev":""}`+"\n"), 0o000); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, 0o600) })

	ev, verdict, ok := LoadControl(p)
	if os.Geteuid() == 0 {
		t.Skip("running as root: file permissions are not enforced, cannot provoke the error verdict")
	}
	if verdict != "error" || !ok {
		t.Fatalf("verdict=%q ok=%v", verdict, ok)
	}
	if len(ev) != 0 {
		t.Fatalf("expected no events, got %+v", ev)
	}
}

// TestConfigJoinIgnoresProvisionAndPrune: a successful provision carries the
// installed hash but installs nothing, so the run's config-join still names
// the apply; a prune carries no hash at all.
func TestConfigJoinIgnoresProvisionAndPrune(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.jsonl")
	dana, mallory := identity.Static("dana@example.com"), identity.Static("mallory@example.com")
	for _, e := range []control.Event{
		{Action: "apply", Outcome: "success", Invoker: dana, Witness: control.CaptureWitness(), ConfigHash: "sha256:aaa"},
		{Action: "provision", Outcome: "success", Invoker: mallory, Witness: control.CaptureWitness(), ConfigHash: "sha256:aaa"},
		{Action: "prune", Outcome: "success", Invoker: mallory, Witness: control.CaptureWitness(), Detail: "pruned 0 run(s) and 0 artifact(s) older than 180d"},
	} {
		if _, err := control.Append(p, e); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	ev, verdict, ok := LoadControl(p)
	if !ok || verdict != "verified" {
		t.Fatalf("verdict=%q ok=%v", verdict, ok)
	}
	line := ConfigJoin(ev, verdict, "sha256:aaa", time.Now())
	if !strings.Contains(line, "applied by dana@example.com") || strings.Contains(line, "mallory") {
		t.Fatalf("the join must name the apply, never the provision: %q", line)
	}
}
