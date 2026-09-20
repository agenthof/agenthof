package control_test

import (
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
	"github.com/agenthof/agenthof/internal/ledger"
)

// TestRepairTornTailMovesFragmentAndTaints covers the happy path (spec
// §3.6): a torn-tail control log is repaired by moving the fragment aside,
// truncating the live file to the last valid record, and appending a
// chained "repair" event that permanently taints the ledger.
func TestRepairTornTailMovesFragmentAndTaints(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	op := identity.Static("dana@example.com")
	if _, err := control.Append(p, control.Event{Action: "apply", Outcome: "success", Invoker: op, Witness: control.CaptureWitness()}); err != nil {
		t.Fatalf("seed apply: %v", err)
	}
	if _, err := control.Append(p, control.Event{Action: "disable", Agent: "coder", Outcome: "success", Invoker: op, Witness: control.CaptureWitness()}); err != nil {
		t.Fatalf("seed disable: %v", err)
	}

	clean, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read clean log: %v", err)
	}

	// Corrupt the tail: a partial line with no trailing newline.
	fragment := []byte(`{"v":"control/1","seq":3,"partial`)
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open for corruption: %v", err)
	}
	if _, err := f.Write(fragment); err != nil {
		t.Fatalf("write fragment: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Confirm the fixture is actually torn before repairing it.
	if _, _, verr := ledger.ReadVerify(p, ledger.Locked); verr == nil {
		t.Fatal("fixture must be torn before Repair is exercised")
	}

	repairOp := identity.Static("ops@example.com")
	witness := control.CaptureWitness()
	fragLen, fragSHA, err := control.Repair(p, repairOp, "ops@example.com", witness)
	if err != nil {
		t.Fatalf("Repair: %v", err)
	}
	if fragLen != len(fragment) {
		t.Fatalf("fragmentLen = %d, want %d", fragLen, len(fragment))
	}
	sum := sha256.Sum256(fragment)
	wantSHA := hex.EncodeToString(sum[:])
	if fragSHA != wantSHA {
		t.Fatalf("fragmentSHA = %s, want %s", fragSHA, wantSHA)
	}

	// The sibling fragment file must exist, be 0600, and hold the exact
	// fragment bytes — and must never be pruned by Repair itself.
	matches, err := filepath.Glob(p + ".torn-*")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("torn fragment files = %v, want exactly 1", matches)
	}
	tornInfo, err := os.Stat(matches[0])
	if err != nil {
		t.Fatalf("stat torn file: %v", err)
	}
	if perm := tornInfo.Mode().Perm(); perm != 0o600 {
		t.Fatalf("torn file mode = %o, want 0600", perm)
	}
	tornContent, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("read torn file: %v", err)
	}
	if string(tornContent) != string(fragment) {
		t.Fatalf("torn file content = %q, want %q", tornContent, fragment)
	}

	// The live file must verify clean again, now with 3 records: the
	// original 2 plus the appended repair event.
	records, head, verr := ledger.ReadVerify(p, ledger.Locked)
	if verr != nil {
		t.Fatalf("post-repair ReadVerify: %v", verr)
	}
	if head.Count != 3 {
		t.Fatalf("head.Count = %d, want 3", head.Count)
	}
	if len(records) != 3 {
		t.Fatalf("len(records) = %d, want 3", len(records))
	}

	// The live file's valid prefix must be byte-identical to the
	// pre-corruption clean log — truncation must land exactly at the end
	// of the last valid record, not before or after it.
	live, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read repaired log: %v", err)
	}
	if !strings.HasPrefix(string(live), string(clean)) {
		t.Fatal("repaired log does not retain the original clean prefix byte-for-byte")
	}

	tainted, seq := control.IsTainted(records)
	if !tainted || seq != 3 {
		t.Fatalf("IsTainted = %v, %d; want true, 3", tainted, seq)
	}

	repairRec := readNthJSON(t, p, 2)
	if repairRec["action"] != "repair" {
		t.Fatalf("repair record action = %v, want repair", repairRec["action"])
	}
	if repairRec["outcome"] != "success" {
		t.Fatalf("repair record outcome = %v, want success", repairRec["outcome"])
	}
	if repairRec["fragment_len"].(float64) != float64(len(fragment)) {
		t.Fatalf("repair record fragment_len = %v, want %d", repairRec["fragment_len"], len(fragment))
	}
	if repairRec["fragment_sha256"] != wantSHA {
		t.Fatalf("repair record fragment_sha256 = %v, want %s", repairRec["fragment_sha256"], wantSHA)
	}
	inv, ok := repairRec["invoker"].(map[string]any)
	if !ok || inv["subject"] != "ops@example.com" {
		t.Fatalf("repair record invoker = %v, want subject ops@example.com", repairRec["invoker"])
	}
	if repairRec["asserted_as"] != "ops@example.com" {
		t.Fatalf("repair record asserted_as = %v, want ops@example.com", repairRec["asserted_as"])
	}
	repairWitness, ok := repairRec["witness"].(map[string]any)
	if !ok {
		t.Fatalf("repair record witness missing or not an object: %+v", repairRec["witness"])
	}
	if repairWitness["os_user"] != witness.OSUser || repairWitness["hostname"] != witness.Hostname {
		t.Fatalf("repair record witness = %+v, want os_user=%q hostname=%q", repairWitness, witness.OSUser, witness.Hostname)
	}
}

// TestRepairTerminatedUnparseableFinalLineTaints covers the brief's other
// named torn shape (spec §3.6): the ledger also classifies a
// terminated-but-unparseable final line — not just a missing trailing
// newline — as a *ledger.TornError. Repair must move that whole garbage
// line into the fragment, truncate back to the clean prefix, and succeed.
func TestRepairTerminatedUnparseableFinalLineTaints(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	op := identity.Static("dana@example.com")
	if _, err := control.Append(p, control.Event{Action: "apply", Outcome: "success", Invoker: op, Witness: control.CaptureWitness()}); err != nil {
		t.Fatalf("seed apply: %v", err)
	}
	clean, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read clean log: %v", err)
	}

	// A garbage line that IS newline-terminated (unlike the other tests'
	// unterminated partial line): invalid JSON, but a complete line.
	fragment := []byte("not json at all\n")
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open for corruption: %v", err)
	}
	if _, err := f.Write(fragment); err != nil {
		t.Fatalf("write fragment: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Confirm the fixture is torn (not chain-broken) despite being
	// newline-terminated.
	_, _, verr := ledger.ReadVerify(p, ledger.Locked)
	if verr == nil {
		t.Fatal("fixture must be torn before Repair is exercised")
	}
	if _, ok := verr.(*ledger.TornError); !ok {
		t.Fatalf("fixture verr = %T, want *ledger.TornError", verr)
	}

	fragLen, fragSHA, err := control.Repair(p, identity.Static("ops@example.com"), "ops@example.com", control.CaptureWitness())
	if err != nil {
		t.Fatalf("Repair: %v", err)
	}
	if fragLen != len(fragment) {
		t.Fatalf("fragmentLen = %d, want %d", fragLen, len(fragment))
	}
	sum := sha256.Sum256(fragment)
	if wantSHA := hex.EncodeToString(sum[:]); fragSHA != wantSHA {
		t.Fatalf("fragmentSHA = %s, want %s", fragSHA, wantSHA)
	}

	matches, err := filepath.Glob(p + ".torn-*")
	if err != nil || len(matches) != 1 {
		t.Fatalf("torn fragment glob = %v, err %v, want exactly one match", matches, err)
	}
	tornContent, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("read torn file: %v", err)
	}
	if string(tornContent) != string(fragment) {
		t.Fatalf("torn file content = %q, want %q", tornContent, fragment)
	}

	live, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read repaired log: %v", err)
	}
	if !strings.HasPrefix(string(live), string(clean)) {
		t.Fatal("repaired log does not retain the original clean prefix byte-for-byte")
	}

	records, head, verr := ledger.ReadVerify(p, ledger.Locked)
	if verr != nil {
		t.Fatalf("post-repair ReadVerify: %v", verr)
	}
	if head.Count != 2 {
		t.Fatalf("head.Count = %d, want 2", head.Count)
	}
	tainted, seq := control.IsTainted(records)
	if !tainted || seq != 2 {
		t.Fatalf("IsTainted = %v, %d; want true, 2", tainted, seq)
	}
}

// TestRepairDoesNotOverwriteExistingFragmentFile covers the review fix:
// a fragment file already sitting at the exact "<path>.torn-<unix-now>"
// name Repair would otherwise choose (a same-second collision, e.g. from
// an earlier repair or a hand-placed decoy) must never be clobbered.
// Repair must pick a different name and leave the pre-existing file's
// content untouched.
func TestRepairDoesNotOverwriteExistingFragmentFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	op := identity.Static("dana@example.com")
	if _, err := control.Append(p, control.Event{Action: "apply", Outcome: "success", Invoker: op, Witness: control.CaptureWitness()}); err != nil {
		t.Fatalf("seed apply: %v", err)
	}
	fragment := []byte(`{"v":"control/1","seq":2,"partial`)
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open for corruption: %v", err)
	}
	if _, err := f.Write(fragment); err != nil {
		t.Fatalf("write fragment: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Pre-create the exact filename Repair would compute for "now", with
	// content that must survive untouched.
	decoyPath := fmt.Sprintf("%s.torn-%d", p, time.Now().Unix())
	const decoyContent = "pre-existing fragment, must not be overwritten"
	if err := os.WriteFile(decoyPath, []byte(decoyContent), 0o600); err != nil {
		t.Fatalf("seed decoy fragment file: %v", err)
	}

	if _, _, err := control.Repair(p, op, "", control.CaptureWitness()); err != nil {
		t.Fatalf("Repair: %v", err)
	}

	decoyAfter, err := os.ReadFile(decoyPath)
	if err != nil {
		t.Fatalf("read decoy after repair: %v", err)
	}
	if string(decoyAfter) != decoyContent {
		t.Fatalf("decoy fragment file was overwritten: %q", decoyAfter)
	}

	matches, err := filepath.Glob(p + ".torn-*")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(matches) != 2 {
		t.Fatalf("torn fragment files = %v, want exactly 2 (decoy + real)", matches)
	}
	var foundReal bool
	for _, m := range matches {
		if m == decoyPath {
			continue
		}
		content, err := os.ReadFile(m)
		if err != nil {
			t.Fatalf("read %s: %v", m, err)
		}
		if string(content) == string(fragment) {
			foundReal = true
		}
	}
	if !foundReal {
		t.Fatalf("no sibling fragment file (other than the decoy) held the real fragment: %v", matches)
	}
}

// TestRepairCleanLogErrors covers Repair's refusal on a chain that
// verifies clean: there is nothing to repair, and the file must be left
// untouched.
func TestRepairCleanLogErrors(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	op := identity.Static("dana@example.com")
	if _, err := control.Append(p, control.Event{Action: "apply", Outcome: "success", Invoker: op, Witness: control.CaptureWitness()}); err != nil {
		t.Fatalf("seed apply: %v", err)
	}
	before, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read before: %v", err)
	}

	if _, _, err := control.Repair(p, op, "", control.CaptureWitness()); err == nil {
		t.Fatal("Repair on a clean log must return an error")
	} else if !strings.Contains(err.Error(), "not torn") {
		t.Fatalf("error = %v, want it to mention the log is not torn", err)
	}

	after, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if string(before) != string(after) {
		t.Fatal("Repair must not modify a clean log it refuses to touch")
	}
	if matches, _ := filepath.Glob(p + ".torn-*"); len(matches) != 0 {
		t.Fatalf("Repair must not create a fragment file when it refuses: %v", matches)
	}
}

// TestRepairChainBrokenNotAutoRepairable covers Repair's refusal on a
// *ledger.ChainBrokenError (a well-formed record disagreeing with the
// chain, not a torn tail): this is not a simple truncation and Repair
// must name the broken line rather than attempt anything.
func TestRepairChainBrokenNotAutoRepairable(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	op := identity.Static("dana@example.com")
	if _, err := control.Append(p, control.Event{Action: "apply", Outcome: "success", Invoker: op, Witness: control.CaptureWitness()}); err != nil {
		t.Fatalf("seed apply: %v", err)
	}
	// A well-formed record whose "prev" disagrees with the actual chain
	// head: parses fine, so it's a ChainBrokenError, not a TornError.
	bad := []byte(`{"v":"control/1","seq":2,"prev":"deadbeef","time":"2026-01-01T00:00:00Z","action":"enable","outcome":"success","invoker":{},"witness":{}}` + "\n")
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open for corruption: %v", err)
	}
	if _, err := f.Write(bad); err != nil {
		t.Fatalf("write bad record: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if _, _, verr := ledger.ReadVerify(p, ledger.Locked); verr == nil {
		t.Fatal("fixture must be chain-broken before Repair is exercised")
	} else if _, ok := verr.(*ledger.ChainBrokenError); !ok {
		t.Fatalf("fixture verr = %T, want *ledger.ChainBrokenError", verr)
	}

	before, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read before: %v", err)
	}

	_, _, err = control.Repair(p, op, "", control.CaptureWitness())
	if err == nil {
		t.Fatal("Repair on a chain-broken log must return an error")
	}
	if !strings.Contains(err.Error(), "not auto-repairable") || !strings.Contains(err.Error(), "2") {
		t.Fatalf("error = %v, want it to name broken line 2 as not auto-repairable", err)
	}

	// A chain-broken refusal must be exactly as non-destructive as a
	// clean-log refusal: no mutation of the live file, and no fragment
	// file created — Repair must not have attempted anything.
	after, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if string(before) != string(after) {
		t.Fatal("Repair must not modify a chain-broken log it refuses to touch")
	}
	if matches, _ := filepath.Glob(p + ".torn-*"); len(matches) != 0 {
		t.Fatalf("Repair must not create a fragment file when it refuses: %v", matches)
	}
}
