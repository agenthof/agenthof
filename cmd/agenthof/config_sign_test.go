package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/config"
)

func signCode(t *testing.T, ctl string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := cmdConfigSign([]string{"--control-log", ctl}, &out)
	return code, out.String()
}

// TestConfigSignRemedyTable: every refusal, with its one remedy.
func TestConfigSignRemedyTable(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	// State A, even with nothing installed: the key state is judged first.
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	if code, out := signCode(t, ctl); code != 1 || out != "config sign: no signing key; run: agenthof config keygen --control-log "+ctl+"\n" {
		t.Fatalf("A: %d %q", code, out)
	}
	// Nothing installed.
	keygenAt(t, ctl)
	if code, out := signCode(t, ctl); code != 1 || out != "config sign: "+msgNoConfigInstalled+" under "+installedStore(ctl)+"; run: agenthof apply --config <dir> --control-log "+ctl+"\n" {
		t.Fatalf("nothing installed: %d %q", code, out)
	}
	// State B.
	if err := os.Remove(signingKeyPath(ctl)); err != nil {
		t.Fatal(err)
	}
	if code, out := signCode(t, ctl); code != 1 || out != "config sign: signing.key missing\n" {
		t.Fatalf("B: %d %q", code, out)
	}
	// State C.
	if err := os.Rename(signingPubPath(ctl), signingKeyPath(ctl)); err != nil {
		t.Fatal(err)
	}
	if code, out := signCode(t, ctl); code != 1 || out != "config sign: signing.pub missing; run: agenthof config keygen --control-log "+ctl+"\n" {
		t.Fatalf("C: %d %q", code, out)
	}
	// Pub/key mismatch, standalone: both ids named, nothing written.
	ctl = filepath.Join(t.TempDir(), "control.jsonl")
	id, _ := keygenAt(t, ctl)
	applyAs(t, pullSample(t), ctl)
	if err := os.WriteFile(signingPubPath(ctl), []byte(goldenPubPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	before := mustRead(t, config.SignaturePath(installedStore(ctl), readPointer(t, ctl)))
	if code, out := signCode(t, ctl); code != 1 || !strings.Contains(out, "(key_id "+id+")") || !strings.Contains(out, "(key_id "+goldenKeyID+")") {
		t.Fatalf("mismatch: %d %q", code, out)
	}
	if !bytes.Equal(before, mustRead(t, config.SignaturePath(installedStore(ctl), readPointer(t, ctl)))) {
		t.Fatal("a mismatch writes nothing")
	}
}

// TestConfigSignRepairsTheSignGap: after the install→record→sign gap, one
// config sign writes the .sig the install would have; a second run is
// "already signed" and touches nothing.
func TestConfigSignRepairsTheSignGap(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := pullSample(t)
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	id, _ := keygenAt(t, ctl)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "after_record_before_sign")
	if code, _ := applyCode(t, root, ctl); code != 1 {
		t.Fatal("the hook must leave the install unsigned")
	}
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "")
	noSig(t, ctl)
	hash := readPointer(t, ctl)
	if code, out := signCode(t, ctl); code != 0 || out != "signed: "+hash+"\nversion: 1  key_id: "+id+"\n" {
		t.Fatalf("%d %q", code, out)
	}
	f := readSig(t, ctl)
	if f.Version != 1 || !config.Verify(signingPub(t, ctl), f.Payload, f.Sig) {
		t.Fatalf("%+v", f)
	}
	p := config.SignaturePath(installedStore(ctl), hash)
	stat1, _ := os.Stat(p)
	if code, out := signCode(t, ctl); code != 0 || out != "already signed: "+hash+"  version: 1  key_id: "+id+"\n" {
		t.Fatalf("%d %q", code, out)
	}
	if stat2, _ := os.Stat(p); !stat2.ModTime().Equal(stat1.ModTime()) {
		t.Fatal("already signed must not rewrite the file")
	}
	noStagingResidue(t, ctl)
}

// TestConfigSignRefusesAnUnvouchedPointer: the crash-gap (pointer moved,
// nothing appended) and a root whose ledger file is gone both answer "not
// yet on record" — never the repair hint, which would be false.
func TestConfigSignRefusesAnUnvouchedPointer(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := pullSample(t)
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	keygenAt(t, ctl)
	applyAs(t, root, ctl)
	writeFileIn(t, root, "agents/planner.yaml", "name: planner\nmodel: fast\ninstruction: plan harder\noutput: plan\nendpoint: http://127.0.0.1:1\n")
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "after_install_before_append")
	_, _ = applyCode(t, root, ctl)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "")
	want := "config sign: installed configuration is not yet on record; re-apply (or audit repair control) first\n"
	if code, out := signCode(t, ctl); code != 1 || out != want {
		t.Fatalf("crash gap: %d %q", code, out)
	}
	noSig(t, ctl)

	if err := os.Remove(ctl); err != nil {
		t.Fatal(err)
	}
	if code, out := signCode(t, ctl); code != 1 || out != want {
		t.Fatalf("no ledger file: %d %q", code, out)
	}
	if _, err := os.Stat(ctl); !os.IsNotExist(err) {
		t.Fatal("config sign must never create the ledger")
	}
}

// TestConfigSignTornLedgerPrintsRepairHint: damage is damage.
func TestConfigSignTornLedgerPrintsRepairHint(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	keygenAt(t, ctl)
	applyAs(t, pullSample(t), ctl)
	appendFragment(t, ctl)
	if code, out := signCode(t, ctl); code != 1 || out != "control ledger damaged; run: agenthof audit repair control --control-log "+ctl+"\n" {
		t.Fatalf("%d %q", code, out)
	}
}

// TestConfigSignNeverRecords: a successful sign leaves the ledger
// byte-identical.
func TestConfigSignNeverRecords(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	keygenAt(t, ctl)
	applyAs(t, pullSample(t), ctl)
	if err := os.Remove(config.SignaturePath(installedStore(ctl), readPointer(t, ctl))); err != nil {
		t.Fatal(err)
	}
	before := mustRead(t, ctl)
	if code, _ := signCode(t, ctl); code != 0 {
		t.Fatal("sign must succeed")
	}
	if !bytes.Equal(before, mustRead(t, ctl)) {
		t.Fatal("config sign must never write the control ledger")
	}
	if len(controlEvents(t, ctl)) != 1 {
		t.Fatal("one event: the apply")
	}
}

// TestConfigSignBusyWhenTheWriterLockIsHeld waits the real lockTimeout;
// t.Parallel, so it runs after every sequential t.Setenv test returned.
func TestConfigSignBusyWhenTheWriterLockIsHeld(t *testing.T) {
	t.Parallel()
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	holdLock(t, "file", installedLock(ctl), 9000)
	var out bytes.Buffer
	if code := cmdConfigSign([]string{"--control-log", ctl}, &out); code != 1 || out.String() != "config sign: "+msgLockBusy+"\n" {
		t.Fatalf("%d %q", code, out.String())
	}
}

func TestConfigSignUsage(t *testing.T) {
	var out bytes.Buffer
	if code := cmdConfigSign([]string{"--bogus"}, &out); code != 2 {
		t.Fatalf("%d", code)
	}
	if code := cmdConfig([]string{"sign", "--bogus"}, &out); code != 2 {
		t.Fatalf("%d", code)
	}
	if !strings.Contains(usage, "agenthof config sign   [--control-log <path>]") {
		t.Fatal("usage must list config sign")
	}
}
