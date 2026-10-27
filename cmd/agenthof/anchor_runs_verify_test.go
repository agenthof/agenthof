package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/anchor/anchortest"
	"github.com/agenthof/agenthof/internal/anchorverify"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/ledger"
	"github.com/agenthof/agenthof/internal/sidecar"
)

func auditRun(f runsFixture, id string, args ...string) (int, string) {
	var out bytes.Buffer
	code := cmdAudit(append([]string{id, "--log-dir", f.logDir, "--control-log", f.ctl}, args...), &out)
	return code, out.String()
}

func auditVerifyRun(f runsFixture, id string, args ...string) (int, string) {
	var out bytes.Buffer
	code := cmdAudit(append([]string{"verify", id, "--log-dir", f.logDir, "--control-log", f.ctl}, args...), &out)
	return code, out.String()
}

// anchoredStubRun is a fixture whose one run is anchored through the stub
// backend (a backend that needs no key, so every verdict is reachable by its
// Fail and Deny switches).
func anchoredStubRun(t *testing.T) (runsFixture, *runsBackend) {
	t.Helper()
	f := newRunsFixture(t)
	b := useRunsBackend(t)
	if code, out, _ := anchorCmd(f.args("--run", f.id)); code != 0 {
		t.Fatalf("anchor: %d\n%s", code, out)
	}
	return f, b
}

// rekorFixture anchors the fixture's run through a real Rekor client against
// the fake, so the ladder's own causes ("no key to verify under") are the ones
// under test. It returns the fake; anchor.pub is not written.
func rekorFixture(t *testing.T) (runsFixture, *anchortest.RekorV1) {
	t.Helper()
	f := newRunsFixture(t)
	fake := anchortest.NewRekorV1()
	t.Cleanup(fake.Close)
	writeIntegrity(t, f.ctl, "anchor: tlog\nanchor_backend:\n  url: "+fake.URL+"\nanchor_runs: on-demand\n")
	if code, out, _ := anchorCmd(f.args("--run", f.id)); code != 0 {
		t.Fatalf("anchor: %d\n%s", code, out)
	}
	return f, fake
}

func pinFake(t *testing.T, f runsFixture, fake *anchortest.RekorV1) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(filepath.Dir(f.ctl), "anchor.pub"), fake.PublicKeyPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestAuditRunUnpinnedAnchoredIsUnverifiable7: audit <id> is offline under the
// pin, always. On an anchored run with no pin there is no key to verify under,
// so the line is unverifiable — with the fix named — and the exit is 7. It is
// never a mismatch. With the pin it is independently verified (offline), and
// audit verify <id> without a pin may fetch the key the log serves and says it
// is not independent.
func TestAuditRunUnpinnedAnchoredIsUnverifiable7(t *testing.T) {
	f, fake := rekorFixture(t)

	code, out := auditRun(f, f.id)
	if code != 7 ||
		!strings.Contains(out, "ledger anchor: unverifiable — no key to verify under (unpinned, offline); pin the log key in anchor.pub beside the control ledger or pass --anchor-key, or run audit verify "+f.id+" to check under the key the log serves\n") ||
		strings.Contains(out, "MISMATCH") || strings.Contains(out, "independently verified") {
		t.Fatalf("exit %d\n%s", code, out)
	}

	// The same run, with the pin: independent, offline, exit 0.
	pinFake(t, f, fake)
	code, out = auditRun(f, f.id)
	if code != 0 || !strings.Contains(out, "ledger anchor: independently verified (log key pinned; offline: presence not checked; events 3 ") {
		t.Fatalf("pinned: exit %d\n%s", code, out)
	}
	reqs := len(fake.Requests())
	// audit <id> never asks the log, pinned or not.
	if _, _ = auditRun(f, f.id); len(fake.Requests()) != reqs {
		t.Fatalf("audit <run-id> made a request to the log: %v", fake.Requests()[reqs:])
	}

	// audit verify, pinned and online: independent, with presence checked.
	code, out = auditVerifyRun(f, f.id)
	if code != 0 || !strings.Contains(out, "ledger anchor: independently verified (log key pinned; events 3 ") || strings.Contains(out, "offline") {
		t.Fatalf("verify pinned: exit %d\n%s", code, out)
	}

	// audit verify without a pin: the key the log serves, said not independent.
	if err := os.Remove(filepath.Join(filepath.Dir(f.ctl), "anchor.pub")); err != nil {
		t.Fatal(err)
	}
	code, out = auditVerifyRun(f, f.id)
	if code != 0 || !strings.Contains(out, "ledger anchor: anchored — verified under the log key as served (not independent; ") || strings.Contains(out, "independently verified") {
		t.Fatalf("verify unpinned: exit %d\n%s", code, out)
	}
}

// TestAuditRunUnreachableOrRotatedKeyIsUnverifiableNeverTampered: a log that
// does not answer, or whose key rotated, is no verdict — 7, never 6, and the
// word "MISMATCH" never appears.
func TestAuditRunUnreachableOrRotatedKeyIsUnverifiableNeverTampered(t *testing.T) {
	f, fake := rekorFixture(t)
	pinFake(t, f, fake)

	fake.Stop()
	code, out := auditVerifyRun(f, f.id)
	if code != 7 || !strings.Contains(out, "ledger anchor: unverifiable — ") || !strings.Contains(out, "(proof verified offline; presence not checked)") || strings.Contains(out, "MISMATCH") {
		t.Fatalf("pinned, log stopped: exit %d\n%s", code, out)
	}
	// Offline there is nothing to reach.
	if code, out = auditVerifyRun(f, f.id, "--offline"); code != 0 || !strings.Contains(out, "offline: presence not checked") {
		t.Fatalf("pinned, offline: exit %d\n%s", code, out)
	}
	// Unpinned and stopped: the served key cannot be fetched, so nothing was
	// verified, and the line does not claim otherwise.
	if err := os.Remove(filepath.Join(filepath.Dir(f.ctl), "anchor.pub")); err != nil {
		t.Fatal(err)
	}
	code, out = auditVerifyRun(f, f.id)
	if code != 7 || !strings.Contains(out, "ledger anchor: unverifiable — ") || strings.Contains(out, "proof verified offline") || strings.Contains(out, "MISMATCH") {
		t.Fatalf("unpinned, log stopped: exit %d\n%s", code, out)
	}

	// The log's key rotated and the operator pinned the new one: the stored
	// proof was signed by the old key, which is no verdict — not tampering.
	fake.Start()
	fake.RotateKey()
	pinFake(t, f, fake)
	code, out = auditRun(f, f.id)
	if code != 7 || !strings.Contains(out, "ledger anchor: unverifiable — log key differs from the pinned key") || strings.Contains(out, "MISMATCH") {
		t.Fatalf("rotated key: exit %d\n%s", code, out)
	}
}

// TestAuditAnchorKeyWithServerIsUsage: a pin the operator names is never
// silently ignored by a server read — exit 2, before any request.
func TestAuditAnchorKeyWithServerIsUsage(t *testing.T) {
	var out bytes.Buffer
	code := cmdAudit([]string{testRunID, "--server", "http://127.0.0.1:1", "--anchor-key", "k.pub"}, &out)
	if code != 2 || out.String() != "audit: --anchor-key is local-only; the server pins anchor.pub beside its own ledger\n" {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
}

// TestAuditRunNoSidecarIsNotAnchoredAndUnchanged: an unanchored run reads
// "not anchored", exits as it always did, and never reads the pin (a garbled
// anchor.pub changes nothing).
func TestAuditRunNoSidecarIsNotAnchoredAndUnchanged(t *testing.T) {
	f := newRunsFixture(t)
	if err := os.WriteFile(filepath.Join(filepath.Dir(f.ctl), "anchor.pub"), []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, run := range []func(runsFixture, string, ...string) (int, string){auditRun, auditVerifyRun} {
		code, out := run(f, f.id)
		if code != 0 || !strings.Contains(out, "ledger completeness: ") || !strings.Contains(out, "ledger anchor: not anchored\n") {
			t.Fatalf("exit %d\n%s", code, out)
		}
	}
}

// TestAuditRunIsPostureBlind: neither command opens integrity.yaml; deleting
// or garbling it changes no byte of output.
func TestAuditRunIsPostureBlind(t *testing.T) {
	f, _ := anchoredStubRun(t)
	for name, run := range map[string]func(runsFixture, string, ...string) (int, string){"audit": auditRun, "audit verify": auditVerifyRun} {
		wantCode, want := run(f, f.id)
		if wantCode != 0 || !strings.Contains(want, "ledger anchor: ") {
			t.Fatalf("%s: exit %d\n%s", name, wantCode, want)
		}
		if err := os.Remove(integrityPath(f.ctl)); err != nil {
			t.Fatal(err)
		}
		if code, got := run(f, f.id); code != wantCode || got != want {
			t.Fatalf("%s without integrity.yaml: exit %d\n%s\nwant\n%s", name, code, got, want)
		}
		writeIntegrity(t, f.ctl, "garbage: [\n")
		if code, got := run(f, f.id); code != wantCode || got != want {
			t.Fatalf("%s with a garbled integrity.yaml: exit %d\n%s\nwant\n%s", name, code, got, want)
		}
	}
}

// TestAuditVerifyAnchorKeyFailsClosed: --anchor-key is the pin whether or not
// the file exists; an absent one is an unverifiable line (7), never usage (2)
// and never silently unpinned.
func TestAuditVerifyAnchorKeyFailsClosed(t *testing.T) {
	f, _ := anchoredStubRun(t)
	code, out := auditVerifyRun(f, f.id, "--anchor-key", filepath.Join(t.TempDir(), "missing.pub"))
	if code != 7 || !strings.Contains(out, "ledger anchor: unverifiable — pinned log key ") || strings.Contains(out, "MISMATCH") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pin := writePEM(t, t.TempDir(), "k.pub", &key.PublicKey)
	code, out = auditVerifyRun(f, f.id, "--anchor-key", pin, "--offline")
	if code != 0 || !strings.Contains(out, "ledger anchor: independently verified (log key pinned; offline: presence not checked; events 3 ") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

// gapEvents is a finished run whose step claims two door calls but records one.
func gapEvents() []engine.Event {
	marker := engine.Event{Type: "workflow_started", DoorAccounting: engine.DoorAccountingAdmission}
	return []engine.Event{marker, {Type: "step_started", Step: "a"}, {Type: "tool_call"}, stamped("step_succeeded", "a", 2), {Type: "workflow_finished", Status: "succeeded"}}
}

const wrongHead = "0000000000000000000000000000000000000000000000000000000000000000"

// TestRunExitPrecedence: 1 > 6 > 11 > 12 > 4 > 7 > 0 over combinations of a
// chain fault, an anchor verdict, a completeness verdict and --expect-head, all
// through cmdAuditVerify on real fixtures; every line prints whichever exit
// wins.
func TestRunExitPrecedence(t *testing.T) {
	const gapID, liveID = "r-00000000000000a1", "r-00000000000000a2"
	cases := []struct {
		name  string
		setup func(t *testing.T, f runsFixture, b *runsBackend) (id string, extra []string)
		want  int
		lines []string
	}{
		{"clean anchored", func(t *testing.T, f runsFixture, b *runsBackend) (string, []string) { return f.id, nil }, 0, []string{"ledger anchor: anchored — verified"}},
		{"unverifiable alone", func(t *testing.T, f runsFixture, b *runsBackend) (string, []string) { b.Fail(); return f.id, nil }, 7, []string{"ledger anchor: unverifiable — stub: unavailable"}},
		{"unverifiable + wrong expect-head", func(t *testing.T, f runsFixture, b *runsBackend) (string, []string) {
			b.Fail()
			return f.id, []string{"--expect-head", wrongHead}
		}, 4, []string{"ledger anchor: unverifiable", "expect-head mismatch"}},
		{"mismatch alone", func(t *testing.T, f runsFixture, b *runsBackend) (string, []string) { b.Deny(); return f.id, nil }, 6, []string{"ledger anchor: MISMATCH — stub: denied"}},
		{"mismatch + wrong expect-head", func(t *testing.T, f runsFixture, b *runsBackend) (string, []string) {
			b.Deny()
			return f.id, []string{"--expect-head", wrongHead}
		}, 6, []string{"ledger anchor: MISMATCH", "expect-head mismatch"}},
		{"gap, anchor fine", func(t *testing.T, f runsFixture, b *runsBackend) (string, []string) {
			return anchorGapRun(t, f, gapID), nil
		}, 11, []string{"ledger completeness: GAP", "ledger anchor: anchored — verified"}},
		{"gap + unverifiable", func(t *testing.T, f runsFixture, b *runsBackend) (string, []string) {
			id := anchorGapRun(t, f, gapID)
			b.Fail()
			return id, nil
		}, 11, []string{"ledger completeness: GAP", "ledger anchor: unverifiable"}},
		{"gap + mismatch", func(t *testing.T, f runsFixture, b *runsBackend) (string, []string) {
			id := anchorGapRun(t, f, gapID)
			b.Deny()
			return id, nil
		}, 6, []string{"ledger completeness: GAP", "ledger anchor: MISMATCH"}},
		{"gap + wrong expect-head", func(t *testing.T, f runsFixture, b *runsBackend) (string, []string) {
			return anchorGapRun(t, f, gapID), []string{"--expect-head", wrongHead}
		}, 11, []string{"ledger completeness: GAP", "expect-head mismatch"}},
		{"unterminated + wrong expect-head", func(t *testing.T, f runsFixture, b *runsBackend) (string, []string) {
			writeRunLedger(t, f.logDir, liveID, engine.Event{Type: "workflow_started", DoorAccounting: engine.DoorAccountingAdmission}, engine.Event{Type: "step_started", Step: "a"})
			return liveID, []string{"--expect-head", wrongHead}
		}, 12, []string{"ledger completeness: UNTERMINATED", "ledger anchor: not anchored", "expect-head mismatch"}},
		{"wrong expect-head alone", func(t *testing.T, f runsFixture, b *runsBackend) (string, []string) {
			return f.id, []string{"--expect-head", wrongHead}
		}, 4, []string{"ledger anchor: anchored — verified", "expect-head mismatch"}},
		{"broken chain + mismatch", func(t *testing.T, f runsFixture, b *runsBackend) (string, []string) {
			b.Deny()
			p := filepath.Join(f.logDir, f.id+".jsonl")
			raw, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			// Corrupt the first record's bytes: the chain no longer links.
			if err := os.WriteFile(p, bytes.Replace(raw, []byte(`"workflow_started"`), []byte(`"workflow_startee"`), 1), 0o600); err != nil {
				t.Fatal(err)
			}
			return f.id, nil
		}, 1, []string{"head: "}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, b := anchoredStubRun(t)
			id, extra := c.setup(t, f, b)
			code, out := auditVerifyRun(f, id, extra...)
			if code != c.want {
				t.Fatalf("exit %d, want %d\n%s", code, c.want, out)
			}
			for _, l := range c.lines {
				if !strings.Contains(out, l) {
					t.Errorf("missing %q in\n%s", l, out)
				}
			}
			if c.want == 1 && strings.Contains(out, "ledger anchor") {
				t.Errorf("a broken chain is judged on nothing else:\n%s", out)
			}
			// audit <id> adopts 6, 11, 12 and 7 the same way (it has no --expect-head).
			if len(extra) == 0 {
				if acode, aout := auditRun(f, id); acode != c.want {
					t.Errorf("audit: exit %d, want %d\n%s", acode, c.want, aout)
				}
			}
		})
	}
}

// anchorGapRun writes a finished run whose completeness is a gap and anchors it.
func anchorGapRun(t *testing.T, f runsFixture, id string) string {
	t.Helper()
	writeRunLedger(t, f.logDir, id, gapEvents()...)
	if code, out, _ := anchorCmd(f.args("--run", id)); code != 0 {
		t.Fatalf("anchor gap run: %d\n%s", code, out)
	}
	return id
}

// TestRunExitCodeTable: the fold itself, over every pair.
func TestRunExitCodeTable(t *testing.T) {
	for _, c := range []struct {
		comp, anchor int
		expect       bool
		want         int
	}{
		{1, 6, true, 1}, {1, 7, false, 1}, {0, 6, true, 6}, {11, 6, false, 6}, {12, 6, false, 6},
		{11, 7, true, 11}, {12, 7, true, 12}, {12, 0, true, 12}, {0, 7, true, 4}, {0, 0, true, 4}, {0, 7, false, 7}, {0, 0, false, 0},
	} {
		if got := runExitCode(c.comp, c.anchor, c.expect); got != c.want {
			t.Errorf("runExitCode(%d, %d, %v) = %d, want %d", c.comp, c.anchor, c.expect, got, c.want)
		}
	}
}

// TestExpectHeadCountFormOnARun: <count>:<hex> is the head the chain must
// reproduce at that event — the "events=N sha256=H" line audit anchor --run
// prints — and <hex> alone still means the current head. A value that is
// neither is usage, before the ledger is read.
func TestExpectHeadCountFormOnARun(t *testing.T) {
	f, _ := anchoredStubRun(t)
	recs, head, err := ledger.ReadVerify(filepath.Join(f.logDir, f.id+".jsonl"), ledger.Unlocked)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(recs[len(recs)-1].Raw)
	hn := hex.EncodeToString(sum[:])
	n := len(recs)
	if hn != head.Hash {
		t.Fatalf("the head is the last record's hash: %s vs %s", head.Hash, hn)
	}
	if code, out := auditVerifyRun(f, f.id, "--expect-head", fmt.Sprintf("%d:%s", n, hn)); code != 0 || strings.Contains(out, "expect-head mismatch") {
		t.Fatalf("N:H_N: exit %d\n%s", code, out)
	}
	if code, out := auditVerifyRun(f, f.id, "--expect-head", hn); code != 0 || strings.Contains(out, "expect-head mismatch") {
		t.Fatalf("<hex>: exit %d\n%s", code, out)
	}
	// An earlier position reproduces its own head.
	early := sha256.Sum256(recs[0].Raw)
	if code, out := auditVerifyRun(f, f.id, "--expect-head", "1:"+hex.EncodeToString(early[:])); code != 0 {
		t.Fatalf("1:H_1: exit %d\n%s", code, out)
	}

	// The same run id reforged: the count form is the one that catches it.
	other := t.TempDir()
	events := []engine.Event{{Type: "workflow_started"}, {Type: "step_started", Step: "a"}, {Type: "workflow_finished", Status: "failed"}}
	writeRunLedger(t, other, f.id, events...)
	var out bytes.Buffer
	if code := cmdAudit([]string{"verify", f.id, "--log-dir", other, "--control-log", f.ctl, "--expect-head", fmt.Sprintf("%d:%s", n, hn)}, &out); code != 4 || !strings.Contains(out.String(), "expect-head mismatch: want "+hn+" at seq 3, got ") {
		t.Fatalf("reforged: exit %d\n%s", code, out.String())
	}
	// A count past the chain is a mismatch, not a panic.
	if code, out := auditVerifyRun(f, f.id, "--expect-head", fmt.Sprintf("%d:%s", n+5, hn)); code != 4 || !strings.Contains(out, "but the chain has 3 records") {
		t.Fatalf("past the chain: exit %d\n%s", code, out)
	}
	for _, bad := range []string{"deadbeef", "x:y", "3:" + hn[:63], "-1:" + hn, strings.ToUpper(hn), "1:1:" + hn} {
		code, out := auditVerifyRun(f, f.id, "--expect-head", bad)
		if code != 2 || out != "audit verify: --expect-head must be <hex> or <count>:<hex> (64 lowercase hex)\n" {
			t.Fatalf("%q: exit %d\n%s", bad, code, out)
		}
	}
}

// childFixture is a root run with one spawned child, both finished, in the
// fixture's log directory; neither is anchored.
func childFixture(t *testing.T) (f runsFixture, b *runsBackend, root, child string) {
	t.Helper()
	f = newRunsFixture(t)
	b = useRunsBackend(t)
	root, child = "r-00000000000000a0", "r-00000000000000c0"
	log, err := engine.OpenLog(f.logDir, child)
	if err != nil {
		t.Fatal(err)
	}
	bind := engine.Binding{Invoker: identity.Static("dana@example.com"), Role: "r", Workflow: "w", RunID: child, ParentRunID: root, Depth: 1}
	marker := engine.Event{Type: "workflow_started", DoorAccounting: engine.DoorAccountingAdmission}
	for i, e := range []engine.Event{marker, {Type: "step_started", Step: "c"}, stamped("step_succeeded", "c", 0), {Type: "workflow_finished", Status: "succeeded"}} {
		e.Time, e.Binding = time.Unix(int64(i), 0).UTC(), bind
		if err := log.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	_ = log.Close()
	writeRunLedger(t, f.logDir, root, marker,
		engine.Event{Type: "step_started", Step: "a"},
		engine.Event{Type: "spawn", Status: "succeeded", ChildRunID: child, Depth: 1},
		stamped("step_succeeded", "a", 1),
		engine.Event{Type: "workflow_finished", Status: "succeeded"})
	return f, b, root, child
}

// TestAuditVerifyRunShowsChildAnchorOnSubtreeLine: a child's own sidecar is
// judged and reported on its subtree line; a child's mismatch is 6 on the
// parent and a child-only unverifiable is 7, while the parent's own line stays
// its own.
func TestAuditVerifyRunShowsChildAnchorOnSubtreeLine(t *testing.T) {
	f, b, root, child := childFixture(t)

	code, out := auditVerifyRun(f, root)
	if code != 0 || !strings.Contains(out, "ledger anchor: not anchored\n") || !strings.Contains(out, "subtree: run "+child+" — integrity verified, completeness complete, anchor not-anchored\n") {
		t.Fatalf("nothing anchored: exit %d\n%s", code, out)
	}

	if code, out, _ := anchorCmd(f.args("--run", child)); code != 0 {
		t.Fatalf("anchor child: %d\n%s", code, out)
	}
	for name, run := range map[string]func(runsFixture, string, ...string) (int, string){"audit verify": auditVerifyRun, "audit": auditRun} {
		code, out = run(f, root)
		if code != 0 || !strings.Contains(out, "ledger anchor: not anchored\n") || !strings.Contains(out, "completeness complete, anchor verified\n") {
			t.Fatalf("%s, child anchored: exit %d\n%s", name, code, out)
		}
	}

	b.Fail()
	for name, run := range map[string]func(runsFixture, string, ...string) (int, string){"audit verify": auditVerifyRun, "audit": auditRun} {
		code, out = run(f, root)
		if code != 7 || !strings.Contains(out, "ledger anchor: not anchored\n") || !strings.Contains(out, "anchor unverifiable\n") || strings.Contains(out, "MISMATCH") {
			t.Fatalf("%s, child unverifiable: exit %d\n%s", name, code, out)
		}
	}

	b2 := useRunsBackend(t) // a fresh stub: the child's proof is the old stub's, signed with the same secret
	b2.Deny()
	for name, run := range map[string]func(runsFixture, string, ...string) (int, string){"audit verify": auditVerifyRun, "audit": auditRun} {
		code, out = run(f, root)
		if code != 6 || !strings.Contains(out, "ledger anchor: not anchored\n") || !strings.Contains(out, "anchor mismatch\n") {
			t.Fatalf("%s, child mismatch: exit %d\n%s", name, code, out)
		}
	}
}

// TestVerifyAnchorsNoneForTheControlLedger: a control ledger that carries only
// run-scoped anchor records has no anchors of its own to verify, and says
// where the run anchors are reported; one that carries none at all keeps its
// old line.
func TestVerifyAnchorsNoneForTheControlLedger(t *testing.T) {
	f, _ := anchoredStubRun(t) // one run-scoped success record
	code, out := verifyControl(t, "--control-log", f.ctl, "--offline")
	if code != 0 || !strings.Contains(out, "anchors: none for the control ledger (run anchors are reported on each run's audit; if this root is meant to be anchored — integrity.yaml anchor: tlog — run: agenthof audit anchor)\n") || strings.Contains(out, "anchors: none (if") {
		t.Fatalf("run-scoped only: exit %d\n%s", code, out)
	}
	bare := applied(t, writeSample(t))
	code, out = verifyControl(t, "--control-log", bare, "--offline")
	if code != 0 || !strings.Contains(out, "anchors: none (if this root is meant to be anchored — integrity.yaml anchor: tlog — run: agenthof audit anchor)\n") || strings.Contains(out, "for the control ledger") {
		t.Fatalf("no anchors: exit %d\n%s", code, out)
	}
}

// TestVerifyRunAnchorReadsNothingWithoutASidecar: no sidecar, no pin read —
// a garbled anchor.pub cannot make an unanchored run unverifiable.
func TestVerifyRunAnchorReadsNothingWithoutASidecar(t *testing.T) {
	f := newRunsFixture(t)
	v, pinned := verifyRunAnchor(f.logDir, f.id, func() (*ecdsa.PublicKey, error) { t.Fatal("pin read"); return nil, nil }, true, 0)
	if v.Found || pinned || runAnchorExit(v, nil) != 0 {
		t.Fatalf("%+v pinned=%v", v, pinned)
	}
	if _, err := os.Stat(sidecar.Path(f.logDir, f.id)); !os.IsNotExist(err) {
		t.Fatal("a sidecar appeared")
	}
}

// TestRunAnchorExit: the worst verdict in the tree, ranked 6 > 7 > 0 — no
// node, root or child, lowers what another raised; a found sidecar that
// yielded no verdict is unverifiable (7), never verified.
func TestRunAnchorExit(t *testing.T) {
	undecided := sidecar.Verdict{Found: true}
	mismatch := sidecar.Verdict{Found: true, Results: []anchorverify.Result{{State: anchorverify.StateMismatch, Cause: "x"}}}
	verified := sidecar.Verdict{Found: true, Results: []anchorverify.Result{{State: anchorverify.StateVerified}}}
	for _, c := range []struct {
		name     string
		root     sidecar.Verdict
		children []sidecar.Verdict
		want     int
	}{
		{"found, no results", undecided, nil, 7},
		{"child unverifiable", sidecar.Verdict{}, []sidecar.Verdict{undecided}, 7},
		{"nothing anchored", sidecar.Verdict{}, nil, 0},
		{"verified everywhere", verified, []sidecar.Verdict{verified}, 0},
		{"root mismatch, child unverifiable", mismatch, []sidecar.Verdict{undecided}, 6},
		{"root unverifiable, child mismatch", undecided, []sidecar.Verdict{mismatch}, 6},
		{"root mismatch, child verified", mismatch, []sidecar.Verdict{verified}, 6},
		{"child mismatch after an unverifiable sibling", verified, []sidecar.Verdict{undecided, mismatch}, 6},
		{"child mismatch before an unverifiable sibling", verified, []sidecar.Verdict{mismatch, undecided}, 6},
	} {
		if got := runAnchorExit(c.root, c.children); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
	// One definition of the codes.
	if exitAnchorMismatch != sidecar.ExitMismatch || exitAnchorUnverifiable != sidecar.ExitUnverifiable || sidecar.ExitMismatch != 6 || sidecar.ExitUnverifiable != 7 {
		t.Errorf("anchor exit codes drifted: %d %d / %d %d", exitAnchorMismatch, exitAnchorUnverifiable, sidecar.ExitMismatch, sidecar.ExitUnverifiable)
	}
}
