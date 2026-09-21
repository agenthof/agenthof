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

func TestConfigJoinNoApplyOnRecord(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.jsonl")
	inv := identity.Static("dana@example.com")
	if _, err := control.Append(p, control.Event{Action: "apply", Outcome: "success", Invoker: inv,
		Witness: control.CaptureWitness(), ConfigHash: "sha256:other"}); err != nil {
		t.Fatalf("append: %v", err)
	}
	ev, verdict, ok := LoadControl(p)
	if !ok || verdict != "verified" {
		t.Fatalf("verdict=%q ok=%v", verdict, ok)
	}
	line := ConfigJoin(ev, verdict, "sha256:aaa", time.Now())
	if !strings.Contains(line, "no successful apply on record") || strings.Contains(line, "matches a later") {
		t.Fatalf("line=%q", line)
	}
}

func TestConfigJoinFlipOnly(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.jsonl")
	inv := identity.Static("dana@example.com")
	if _, err := control.Append(p, control.Event{Action: "disable", Outcome: "success", Invoker: inv,
		Witness: control.CaptureWitness(), ConfigHash: "sha256:aaa"}); err != nil {
		t.Fatalf("append: %v", err)
	}
	ev, verdict, ok := LoadControl(p)
	if !ok || verdict != "verified" {
		t.Fatalf("verdict=%q ok=%v", verdict, ok)
	}
	line := ConfigJoin(ev, verdict, "sha256:aaa", time.Now())
	if !strings.Contains(line, "no successful apply on record (matches a later enable/disable, not an apply)") {
		t.Fatalf("line=%q", line)
	}
}

func TestConfigJoinApplyAfterRunStartExcluded(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.jsonl")
	inv := identity.Static("dana@example.com")
	runStart := time.Now()
	// Apply happens strictly after runStart: must not count as the join.
	time.Sleep(2 * time.Millisecond)
	if _, err := control.Append(p, control.Event{Action: "apply", Outcome: "success", Invoker: inv,
		Witness: control.CaptureWitness(), ConfigHash: "sha256:aaa"}); err != nil {
		t.Fatalf("append: %v", err)
	}
	ev, verdict, ok := LoadControl(p)
	if !ok || verdict != "verified" {
		t.Fatalf("verdict=%q ok=%v", verdict, ok)
	}
	line := ConfigJoin(ev, verdict, "sha256:aaa", runStart)
	// A later-successful apply is still an apply, not an enable/disable
	// flip: it must fall through to the plain branch-3 wording, not the
	// "matches a later enable/disable, not an apply" branch-2 wording.
	want := "config sha256:aaa — no successful apply on record"
	if line != want {
		t.Fatalf("line=%q want=%q", line, want)
	}
	if strings.Contains(line, "enable/disable") {
		t.Fatalf("line=%q must not mention enable/disable for a later apply", line)
	}
}

func TestConfigJoinFailedApply(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.jsonl")
	inv := identity.Static("dana@example.com")
	if _, err := control.Append(p, control.Event{Action: "apply", Outcome: "failed",
		Reason:  &control.Reason{Code: control.CodeValidationFailed, Message: "bad config"},
		Invoker: inv, Witness: control.CaptureWitness(), ConfigHash: "sha256:aaa"}); err != nil {
		t.Fatalf("append: %v", err)
	}
	ev, verdict, ok := LoadControl(p)
	if !ok || verdict != "verified" {
		t.Fatalf("verdict=%q ok=%v", verdict, ok)
	}
	line := ConfigJoin(ev, verdict, "sha256:aaa", time.Now())
	want := "config sha256:aaa — no successful apply on record"
	if line != want {
		t.Fatalf("line=%q want=%q", line, want)
	}
	if strings.Contains(line, "enable/disable") {
		t.Fatalf("line=%q must not mention enable/disable for a failed apply", line)
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
