package main

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/control"
)

// withHistory plants a manifest beside ctl and removes the active: a root
// with history and no active — FaultActiveMissing, never "nothing recorded".
func withHistory(t *testing.T, ctl string) {
	t.Helper()
	m := `{"v":"segments/1","log_id":"` + strings.Repeat("ab", 16) + `","segments":[]}`
	if err := os.WriteFile(control.ManifestPath(ctl), []byte(m), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(ctl); err != nil {
		t.Fatal(err)
	}
}

// TestActiveMissingWithHistoryIsNotNotExist: audit control, audit verify
// control and audit repair control print the FaultActiveMissing text and
// exit 1 — never "nothing recorded yet" — and vouchInstalled reports
// not-verifiable, never "no install on record".
func TestActiveMissingWithHistoryIsNotNotExist(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	ctl := applied(t, root)
	withHistory(t, ctl)
	for _, args := range [][]string{
		{"control", "--control-log", ctl},
		{"verify", "control", "--control-log", ctl},
		{"repair", "control", "--control-log", ctl, "--config", root, "--as", "dana@example.com", "--groups", "platform-eng"},
	} {
		var out bytes.Buffer
		code := cmdAudit(args, &out)
		if code != 1 || strings.Contains(out.String(), "nothing recorded yet") || !strings.Contains(out.String(), "control ledger active segment missing") {
			t.Fatalf("%v: exit %d\n%s", args, code, out.String())
		}
	}
	_, _, refusal := vouchInstalled(ctl, readPointer(t, ctl))
	if refusal == nil || refusal.Kind != verifyNotVerifiable || strings.Contains(refusal.Error(), "no install on record") || strings.Contains(refusal.Error(), "audit repair control") {
		t.Fatalf("vouchInstalled: %v", refusal)
	}
	if _, err := os.Lstat(ctl); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("no reader may recreate the active")
	}
}

// TestVouchInstalledOnASetFault: a sealed-segment or structural fault is
// not-verifiable with the seam's text and no repair hint; a torn active
// keeps today's repair hint.
func TestVouchInstalledOnASetFault(t *testing.T) {
	ctl := applied(t, writeSample(t))
	if err := os.WriteFile(control.SegmentPath(ctl, 3), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, refusal := vouchInstalled(ctl, readPointer(t, ctl))
	if refusal == nil || refusal.Kind != verifyNotVerifiable || !strings.Contains(refusal.Error(), "but no manifest") || strings.Contains(refusal.Error(), "audit repair control") {
		t.Fatalf("set fault: %v", refusal)
	}
	_ = os.Remove(control.SegmentPath(ctl, 3))
	tearTail(t, ctl)
	_, _, refusal = vouchInstalled(ctl, readPointer(t, ctl))
	if refusal == nil || !strings.Contains(refusal.Error(), "run: agenthof audit repair control") {
		t.Fatalf("torn active: %v", refusal)
	}
}

// TestWritablePrechecksClassify: busy, torn (the repair hint, with --config
// where the command has one), and a structural fault (its own text) at
// apply's and the shared precheck.
func TestWritablePrechecksClassify(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	ctl := applied(t, root)
	if err := os.WriteFile(control.SegmentPath(ctl, 1), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if code := cmdApply([]string{"--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 1 || !strings.Contains(out.String(), "but no manifest") || strings.Contains(out.String(), "audit repair control") {
		t.Fatalf("apply on a set fault: %d\n%s", code, out.String())
	}
	out.Reset()
	if ok := controlLedgerWritable("runs prune", ctl, &out); ok || !strings.Contains(out.String(), "runs prune: control ledger has segment files") {
		t.Fatalf("precheck: %v %s", ok, out.String())
	}
	_ = os.Remove(control.SegmentPath(ctl, 1))
	tearTail(t, ctl)
	out.Reset()
	if code := cmdApply([]string{"--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 1 || out.String() != "control ledger damaged; run: agenthof audit repair control --control-log "+ctl+" --config "+root+"\n" {
		t.Fatalf("apply on a torn active must print exactly today's hint: %d\n%s", code, out.String())
	}
}
