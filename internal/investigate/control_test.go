package investigate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
	const want = "config sha256:aaa — no install on record at the run's start (matches a later apply, kill-switch flip or vouch)"
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

// TestConfigJoinVouchInstall: a run whose hash the ledger vouched for (a
// vouch event, no apply row) joins to the sixth form — never the flip form
// with an empty agent.
func TestConfigJoinVouchInstall(t *testing.T) {
	ev := joinFixture(t,
		control.Event{Action: "apply", Outcome: "success", ConfigHash: "sha256:aaa"},
		control.Event{Action: "vouch", Outcome: "success", ConfigHash: "sha256:fff", Detail: "previously on record: sha256:aaa, apply"})
	line := ConfigJoin(ev, "verified", "sha256:fff", time.Now())
	want := "config sha256:fff — vouched for by dana@example.com (asserted) at " + ev[1].Time.Format(time.RFC3339)
	if line != want {
		t.Fatalf("line=%q\nwant=%q", line, want)
	}
	if strings.Contains(line, "kill switch") || strings.Contains(line, "agent ") {
		t.Fatalf("never the flip form: %q", line)
	}
}

// TestConfigJoinLaterFormNamesVouch: the later-install form's parenthetical
// names all three installing actions.
func TestConfigJoinLaterFormNamesVouch(t *testing.T) {
	ev := joinFixture(t, control.Event{Action: "vouch", Outcome: "success", ConfigHash: "sha256:aaa"})
	line := ConfigJoin(ev, "verified", "sha256:aaa", ev[0].Time.Add(-time.Hour))
	if line != "config sha256:aaa — no install on record at the run's start (matches a later apply, kill-switch flip or vouch)" {
		t.Fatalf("line=%q", line)
	}
}

// TestConfigJoinIgnoresAnAnchorWithTheRunsHash: an anchor record carrying
// the run's config_hash — set on purpose, malformed — is excluded by the
// Installing predicate, not by the hash: the join names the apply, never the
// anchor's invoker.
func TestConfigJoinIgnoresAnAnchorWithTheRunsHash(t *testing.T) {
	t0 := time.Date(2026, 10, 13, 10, 0, 0, 0, time.UTC)
	ev := []control.DecodedEvent{
		{Seq: 1, Time: t0, Action: "apply", Outcome: "success", ConfigHash: "sha256:aaa", Invoker: identity.Invoker{Subject: "dana@example.com", Issuer: "local", Method: "asserted"}},
		{Seq: 2, Time: t0.Add(time.Minute), Action: "anchor", Outcome: "success", ConfigHash: "sha256:aaa",
			Invoker: identity.Invoker{Subject: "anchor-bot", Issuer: "local", Method: "asserted"},
			Anchor:  &control.Anchor{Seq: 1, Hash: strings.Repeat("ab", 32), Kind: "tlog", Ref: "1"}},
	}
	line := ConfigJoin(ev, "verified", "sha256:aaa", t0.Add(2*time.Minute))
	if want := "config sha256:aaa — applied by dana@example.com (asserted) at " + t0.Format(time.RFC3339); line != want {
		t.Fatalf("line=%q\nwant=%q", line, want)
	}
	if strings.Contains(line, "anchor-bot") {
		t.Fatalf("the anchor must never be the install: %q", line)
	}
}

// TestLoadControlDecodesAnAnchorRecord: a ledger holding a hand-built,
// correctly chained anchor record loads verified, decodes the payload, and
// normalizes to kind "anchor" with no payload on the investigate/1 wire.
func TestLoadControlDecodesAnAnchorRecord(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.jsonl")
	if _, err := control.Append(p, control.Event{Action: "apply", Outcome: "success", Invoker: identity.Static("dana@example.com"),
		Witness: control.CaptureWitness(), ConfigHash: "sha256:aaa"}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	// prev is the SHA-256 of the previous line's exact bytes, without its "\n".
	sum := sha256.Sum256(bytes.TrimSuffix(raw, []byte("\n")))
	prev := hex.EncodeToString(sum[:])
	line := fmt.Sprintf(`{"v":"control/1","seq":2,"time":"2026-10-13T10:02:00Z","action":"anchor","outcome":"success",`+
		`"invoker":{"subject":"anchor-bot","issuer":"local","method":"asserted"},"witness":{"os_user":"dana","hostname":"host"},`+
		`"anchor":{"seq":1,"hash":%q,"kind":"tlog","backend_kind":"transparency-log","backend":"https://log.example","ref":"12345"},"prev":%q}`+"\n", prev, prev)
	if err := os.WriteFile(p, append(raw, line...), 0o600); err != nil {
		t.Fatal(err)
	}
	ev, verdict, ok := LoadControl(p)
	if !ok || verdict != "verified" || len(ev) != 2 {
		t.Fatalf("verdict=%q ok=%v events=%d", verdict, ok, len(ev))
	}
	if ev[1].Action != "anchor" || ev[1].Anchor == nil || ev[1].Anchor.Seq != 1 || ev[1].Anchor.Hash != prev || ev[1].Anchor.Ref != "12345" {
		t.Fatalf("anchor event: %+v", ev[1])
	}
	r := normalizeControl(ev[1], nil)
	if r.Kind != "anchor" || r.Source != "control" || r.Seq != 2 || r.ConfigHash != "" {
		t.Fatalf("normalized: %+v", r)
	}
}

// TestLoadControlVerdictsOverASet: a torn active is "torn"; a planted
// unexpected segment is "broken" (never "missing"); a manifest beside a
// missing active is "broken" (never "missing"); no root at all is "missing".
func TestLoadControlVerdictsOverASet(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	inv := identity.Static("dana@example.com")
	if _, err := control.Append(p, control.Event{Action: "apply", Outcome: "success", Invoker: inv, Witness: control.CaptureWitness(), ConfigHash: "sha256:a"}); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{"torn`)
	_ = f.Close()
	if ev, verdict, ok := LoadControl(p); verdict != "torn" || !ok || len(ev) != 1 {
		t.Fatalf("torn active: %q %v %d", verdict, ok, len(ev))
	}
	if err := os.Truncate(p, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := control.Append(p, control.Event{Action: "apply", Outcome: "success", Invoker: inv, Witness: control.CaptureWitness(), ConfigHash: "sha256:a"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(control.SegmentPath(p, 1), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ev, verdict, ok := LoadControl(p); verdict != "broken" || !ok || len(ev) != 0 {
		t.Fatalf("unexpected segment: %q %v %d", verdict, ok, len(ev))
	}
	_ = os.Remove(control.SegmentPath(p, 1))
	_ = os.WriteFile(control.ManifestPath(p), []byte(`{"v":"segments/1","log_id":"`+strings.Repeat("ab", 16)+`","segments":[]}`), 0o600)
	_ = os.Remove(p)
	if _, verdict, ok := LoadControl(p); verdict != "broken" || !ok {
		t.Fatalf("active missing with a manifest: %q %v", verdict, ok)
	}
	if _, verdict, ok := LoadControl(filepath.Join(t.TempDir(), "none.jsonl")); verdict != "missing" || ok {
		t.Fatalf("no root: %q %v", verdict, ok)
	}
}

// TestLoadControlReadsAcrossASealedSegment: the events of a sealed segment
// and of the continuation active are one chain — the seal event is in it,
// the verdict is verified, and the records are the whole logical chain.
func TestLoadControlReadsAcrossASealedSegment(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	inv := identity.Static("dana@example.com")
	ev := control.Event{Action: "apply", Outcome: "success", Invoker: inv, Witness: control.CaptureWitness(), ConfigHash: "sha256:a"}
	for i := 0; i < 2; i++ {
		if _, err := control.Append(p, ev); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := control.SealActive(p, control.Event{Action: "seal", Outcome: "success", Invoker: inv, Witness: control.CaptureWitness()}); err != nil {
		t.Fatal(err)
	}
	if _, err := control.Append(p, ev); err != nil {
		t.Fatal(err)
	}
	recs, events, verdict, ok := loadControl(p)
	if verdict != "verified" || !ok || len(recs) != 4 || len(events) != 4 {
		t.Fatalf("%q %v %d %d", verdict, ok, len(recs), len(events))
	}
	if events[2].Action != "seal" || events[3].Seq != 4 {
		t.Fatalf("%+v", events)
	}
}
