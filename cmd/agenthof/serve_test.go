package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/config"
)

func TestLoopbackAddr(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:0": true, "localhost:8080": true, "[::1]:8080": true,
		"0.0.0.0:8080": false, ":8080": false, "10.0.0.5:80": false, "nonsense": false,
	} {
		if got := loopbackAddr(addr); got != want {
			t.Errorf("loopbackAddr(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestServeRefusesToStartWithoutAnIssuer(t *testing.T) {
	t.Setenv("AGENTHOF_OIDC_ISSUER", "")
	var out bytes.Buffer
	if code := cmdServe(context.Background(), []string{"--addr", "127.0.0.1:0"}, &out, io.Discard); code != 2 {
		t.Fatalf("code %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "AGENTHOF_OIDC_ISSUER") {
		t.Fatalf("must say what is missing: %s", out.String())
	}
}

func TestServeRefusesNonLoopbackWithoutTheFlag(t *testing.T) {
	t.Setenv("AGENTHOF_OIDC_ISSUER", "https://idp.test")
	var out bytes.Buffer
	if code := cmdServe(context.Background(), []string{"--addr", "0.0.0.0:0"}, &out, io.Discard); code != 2 {
		t.Fatalf("code %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "--allow-non-loopback") {
		t.Fatalf("must name the flag: %s", out.String())
	}
}

func TestServeWritesAddrFileAnswersHealthzAndStopsOnContext(t *testing.T) {
	t.Chdir(t.TempDir())
	root := writeSample(t)
	t.Setenv("AGENTHOF_OIDC_ISSUER", "https://idp.test") // never dialed: /healthz is unauthenticated
	addrFile := filepath.Join(t.TempDir(), "addr")
	ctx, cancel := context.WithCancel(context.Background())
	var out bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- cmdServe(ctx, []string{"--addr", "127.0.0.1:0", "--addr-file", addrFile, "--config", root, "--log-dir", t.TempDir()}, &out, io.Discard)
	}()
	var addr string
	deadline := time.Now().Add(5 * time.Second)
	for addr == "" && time.Now().Before(deadline) {
		if b, err := os.ReadFile(addrFile); err == nil {
			addr = strings.TrimSpace(string(b))
		}
		time.Sleep(10 * time.Millisecond)
	}
	if addr == "" {
		t.Fatalf("addr file never appeared\n%s", out.String())
	}
	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz = %d", resp.StatusCode)
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("serve exited %d\n%s", code, out.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not stop after its context ended")
	}
	if !strings.Contains(out.String(), "serving on "+addr) {
		t.Fatalf("stdout must announce the address:\n%s", out.String())
	}
}

// TestResolveRunConfigReadsTheInstalledSnapshot pins the swap: the run
// configuration is the installed snapshot beside the control log, the hash
// is the pointer's value verbatim, the --config directory is irrelevant once
// something is installed, and errors are reported before the installed flag
// so a malformed pointer never reads as "run apply first".
func TestResolveRunConfigReadsTheInstalledSnapshot(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)

	empty := filepath.Join(t.TempDir(), "control.jsonl")
	if _, reg, hash, installed, errs, _ := resolveRunConfig(empty, "", verifyAndAdvance); installed || reg != nil || hash != "" || len(errs) != 0 {
		t.Fatalf("nothing installed: installed=%v reg=%v hash=%q errs=%v", installed, reg, hash, errs)
	}

	ctl := applied(t, root)
	cfg, reg, hash, installed, errs, _ := resolveRunConfig(ctl, "", verifyAndAdvance)
	if !installed || len(errs) != 0 || reg == nil || len(cfg.Agents) != 2 {
		t.Fatalf("installed: installed=%v reg=%v errs=%v", installed, reg, errs)
	}
	if hash != readPointer(t, ctl) {
		t.Fatalf("hash must be the pointer verbatim: %q vs %q", hash, readPointer(t, ctl))
	}

	// The directory is not what runs: break it and nothing changes.
	if err := os.WriteFile(filepath.Join(root, "gateway.yaml"), []byte("models: {\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, reg, again, _, errs, _ := resolveRunConfig(ctl, "", verifyAndAdvance); reg == nil || again != hash || len(errs) != 0 {
		t.Fatalf("a broken directory must not affect the installed resolution: hash=%q errs=%v", again, errs)
	}

	// Verify-on-read: an in-place edit under installed/<hex>/ is a mismatch
	// against the pointer, refused before the bytes are parsed — so the
	// edit's own effect (a disabled agent) is never what surfaces. A real
	// kill-switch flip is what makes disabled-agent-ref reach a run.
	store := installedStore(ctl)
	coder := filepath.Join(config.SnapshotDir(store, hash), "agents", "coder.yaml")
	data, err := os.ReadFile(coder)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(coder, append(data, []byte("enabled: false\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := config.HashDir(config.SnapshotDir(store, hash))
	if err != nil {
		t.Fatal(err)
	}
	want := "installed config " + hash + ": snapshot hashes as " + got + ", not as its pointer"
	if _, reg, _, installed, errs, _ := resolveRunConfig(ctl, "", verifyAndAdvance); reg != nil || !installed || len(errs) != 1 || errs[0].Error() != want {
		t.Fatalf("the mismatch must surface, alone: reg=%v installed=%v errs=%v", reg, installed, errs)
	}

	// A malformed pointer: errors first, installed=false.
	if err := os.WriteFile(filepath.Join(store, config.InstalledPointer), []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, reg, hash, installed, errs, _ := resolveRunConfig(ctl, "", verifyAndAdvance); reg != nil || installed || hash != "" || len(errs) != 1 || !strings.Contains(errs[0].Error(), "malformed pointer") {
		t.Fatalf("malformed pointer: reg=%v installed=%v hash=%q errs=%v", reg, installed, hash, errs)
	}
}

// dropInSnapshot copies the installed snapshot, changes one byte of it (a
// YAML comment, so it still loads), writes the copy under the store under its
// own correct hash and aims the pointer at it — a snapshot nothing applied.
func dropInSnapshot(t *testing.T, ctl string) string {
	t.Helper()
	store := installedStore(ctl)
	src := config.SnapshotDir(store, readPointer(t, ctl))
	staged := filepath.Join(t.TempDir(), "staged")
	if err := copyDir(src, staged); err != nil {
		t.Fatal(err)
	}
	planner := filepath.Join(staged, "agents", "planner.yaml")
	data, err := os.ReadFile(planner)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(planner, append(data, []byte("# dropped in\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	hash, err := config.HashDir(staged)
	if err != nil {
		t.Fatal(err)
	}
	if err := copyDir(staged, config.SnapshotDir(store, hash)); err != nil {
		t.Fatal(err)
	}
	repointTo(t, ctl, hash)
	return hash
}

// TestResolveRunConfigRefusesAnInstallTheLedgerDoesNotVouchFor: unpinned,
// a hand-aimed pointer, a dropped-in snapshot and the install→record gap are
// each a not-on-record verdict (cfg loaded, reg nil, hash the pointer,
// installed, errs nil); a re-apply heals; a damaged ledger is not verifiable
// with the repair hint and a repaired ledger runs.
func TestResolveRunConfigRefusesAnInstallTheLedgerDoesNotVouchFor(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	ctl := applied(t, root)
	hashA := readPointer(t, ctl)
	expectNOR := func(name, hash, detailPrefix string) {
		t.Helper()
		before := ledgerBytes(t, ctl)
		cfg, reg, h, installed, errs, unverified := resolveRunConfig(ctl, "", verifyAndAdvance)
		if !bytes.Equal(before, ledgerBytes(t, ctl)) {
			t.Fatalf("%s: a resolve must never write the control ledger", name)
		}
		if unverified == nil || unverified.Kind != verifyNotOnRecord || unverified.Headline() != "configuration not on record" || !strings.HasPrefix(unverified.Detail, detailPrefix) {
			t.Fatalf("%s: unverified=%v reg=%v errs=%v", name, unverified, reg, errs)
		}
		if reg != nil || h != hash || !installed || errs != nil || len(cfg.Agents) == 0 || unverified.Transient() {
			t.Fatalf("%s: a verdict ⇒ cfg loaded, reg nil, hash the pointer, installed, errs nil: reg=%v h=%q installed=%v errs=%v", name, reg, h, installed, errs)
		}
	}

	// hand-aimed: apply B, re-point to A.
	writeFileIn(t, root, "agents/planner.yaml", "name: planner\nmodel: fast\ninstruction: plan harder\noutput: plan\nendpoint: http://127.0.0.1:1\n")
	applyAs(t, root, ctl)
	hashB := readPointer(t, ctl)
	repointTo(t, ctl, hashA)
	expectNOR("hand-aimed", hashA, "last recorded install is "+hashB+" (apply); re-apply")
	// re-apply heals: the directory is B; CommitSnapshot's identical branch re-points.
	applyAs(t, root, ctl)
	if _, reg, h, _, errs, unverified := resolveRunConfig(ctl, "", verifyAndAdvance); reg == nil || h != hashB || errs != nil || unverified != nil {
		t.Fatalf("re-apply heals: h=%q errs=%v unverified=%v", h, errs, unverified)
	}

	// dropped-in: bytes verify, no record.
	hashX := dropInSnapshot(t, ctl)
	expectNOR("dropped-in", hashX, "last recorded install is "+hashB+" (apply); re-apply")
	repointTo(t, ctl, hashB)

	// crash gap: the pointer moves, the append never runs.
	writeFileIn(t, root, "agents/planner.yaml", "name: planner\nmodel: fast\ninstruction: plan hardest\noutput: plan\nendpoint: http://127.0.0.1:1\n")
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "after_install_before_append")
	_, _ = applyCode(t, root, ctl)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "")
	hashC := readPointer(t, ctl)
	if hashC == hashB {
		t.Fatal("the crash hook must have moved the pointer")
	}
	expectNOR("crash gap", hashC, "last recorded install is "+hashB+" (apply); re-apply")
	applyAs(t, root, ctl)
	if _, reg, _, _, errs, unverified := resolveRunConfig(ctl, "", verifyAndAdvance); reg == nil || errs != nil || unverified != nil {
		t.Fatalf("re-apply after the gap: %v %v", errs, unverified)
	}

	// damaged ledger: not verifiable with the hint; repaired → runs.
	appendFragment(t, ctl)
	_, reg, _, installed, errs, unverified := resolveRunConfig(ctl, "", verifyAndAdvance)
	if unverified == nil || unverified.Kind != verifyNotVerifiable || unverified.Detail != "control ledger damaged; run: agenthof audit repair control --control-log "+ctl || reg != nil || !installed || errs != nil {
		t.Fatalf("damaged: unverified=%v reg=%v errs=%v", unverified, reg, errs)
	}
	repairAs(t, root, ctl)
	if _, reg, _, _, errs, unverified := resolveRunConfig(ctl, "", verifyAndAdvance); reg == nil || errs != nil || unverified != nil {
		t.Fatalf("a repaired ledger vouches: %v %v", errs, unverified)
	}
	// removed ledger, pointer present: not on record, never damaged.
	if err := os.Remove(ctl); err != nil {
		t.Fatal(err)
	}
	expectNOR("removed ledger", hashC, "no install on record; re-apply")
	if _, err := os.Stat(ctl); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("a resolve must never create the control ledger")
	}
}

// TestResolveRunConfigPrecedenceAroundTheVouch: load errors come BEFORE the
// vouch (an in-place edit AND a hand-aimed pointer → the mismatch alone,
// unverified nil), and validation comes AFTER it (a hand-aimed pointer at a
// kill-switch re-snapshot that fails Build → not on record, errs nil — Build
// never ran on an unvouched install).
func TestResolveRunConfigPrecedenceAroundTheVouch(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	ctl := applied(t, root)
	hashA := readPointer(t, ctl)
	store := installedStore(ctl)

	// A flip against the install: snapshot F (coder disabled) does not Build.
	var out bytes.Buffer
	if code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("flip: %d\n%s", code, out.String())
	}
	hashF := readPointer(t, ctl)
	if _, reg, _, installed, errs, unverified := resolveRunConfig(ctl, "", verifyAndAdvance); reg != nil || !installed || unverified != nil || len(errs) == 0 || !strings.Contains(errs[0].Error(), "disabled") {
		t.Fatalf("the recorded flip is vouched and then fails Build: reg=%v errs=%v unverified=%v", reg, errs, unverified)
	}
	// Re-apply (the directory is unchanged: back to A, seq 3), then hand-aim at F.
	applyAs(t, root, ctl)
	if readPointer(t, ctl) != hashA {
		t.Fatal("re-apply re-asserts A")
	}
	repointTo(t, ctl, hashF)
	if _, reg, h, installed, errs, unverified := resolveRunConfig(ctl, "", verifyAndAdvance); unverified == nil || unverified.Kind != verifyNotOnRecord || errs != nil || reg != nil || !installed || h != hashF {
		t.Fatalf("validation never runs on an unvouched install: reg=%v errs=%v unverified=%v", reg, errs, unverified)
	}
	repointTo(t, ctl, hashA)

	// Load error AND hand-aimed pointer: the mismatch alone.
	writeFileIn(t, root, "agents/planner.yaml", "name: planner\nmodel: fast\ninstruction: plan harder\noutput: plan\nendpoint: http://127.0.0.1:1\n")
	applyAs(t, root, ctl) // B is now the last install
	repointTo(t, ctl, hashA)
	coder := filepath.Join(config.SnapshotDir(store, hashA), "agents", "coder.yaml")
	data, err := os.ReadFile(coder)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(coder, append(data, []byte("enabled: false\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, reg, _, installed, errs, unverified := resolveRunConfig(ctl, "", verifyAndAdvance); reg != nil || !installed || len(errs) != 1 || !strings.Contains(errs[0].Error(), "not as its pointer") || unverified != nil {
		t.Fatalf("load errors first, alone: reg=%v errs=%v unverified=%v", reg, errs, unverified)
	}
}

// TestResolveRunConfigNothingInstalledReadsNoLedger: with nothing installed
// the answer is installed=false, errs nil, unverified nil whether or not a
// ledger exists (the ledger is never read), but installed.lock IS created —
// the lock precedes LoadInstalled; nothing else is written.
func TestResolveRunConfigNothingInstalledReadsNoLedger(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := filepath.Join(t.TempDir(), "sub", "control.jsonl")
	if _, reg, hash, installed, errs, unverified := resolveRunConfig(ctl, "", verifyAndAdvance); installed || reg != nil || hash != "" || errs != nil || unverified != nil {
		t.Fatalf("empty root: installed=%v reg=%v hash=%q errs=%v unverified=%v", installed, reg, hash, errs, unverified)
	}
	if _, err := os.Stat(installedLock(ctl)); err != nil {
		t.Fatalf("the lock precedes LoadInstalled, so it is created: %v", err)
	}
	names := mustReadDirNames(t, filepath.Dir(ctl))
	if len(names) != 1 || names[0] != "installed.lock" {
		t.Fatalf("nothing else is written: %v", names)
	}
	// A root with a ledger but nothing installed: the same answer — the
	// ledger is not read (a torn one changes nothing).
	root := writeSample(t)
	ctl2 := filepath.Join(t.TempDir(), "control.jsonl")
	var out bytes.Buffer
	if code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", ctl2, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("bootstrap flip: %d\n%s", code, out.String())
	}
	appendFragment(t, ctl2)
	if _, reg, _, installed, errs, unverified := resolveRunConfig(ctl2, "", verifyAndAdvance); installed || reg != nil || errs != nil || unverified != nil {
		t.Fatalf("nothing installed, torn ledger: installed=%v errs=%v unverified=%v", installed, errs, unverified)
	}
}

// startServeOnce starts serve on ctl with a stderr buffer, waits for the
// address file, stops it, and returns the operational log.
func startServeOnce(t *testing.T, ctl string) string {
	t.Helper()
	return startServeOnceWithin(t, ctl, 5*time.Second)
}

// startServeOnceWithin is startServeOnce with a chosen deadline for the
// address file — for a startup that must first wait out lockTimeout.
func startServeOnceWithin(t *testing.T, ctl string, within time.Duration) string {
	t.Helper()
	t.Chdir(t.TempDir())                                 // serve's relative defaults land here, never in the repo
	t.Setenv("AGENTHOF_OIDC_ISSUER", "https://idp.test") // never dialed
	addrFile := filepath.Join(t.TempDir(), "addr")
	ctx, cancel := context.WithCancel(context.Background())
	var out, logs bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- cmdServe(ctx, []string{"--addr", "127.0.0.1:0", "--addr-file", addrFile, "--control-log", ctl, "--log-dir", t.TempDir()}, &out, &logs)
	}()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(addrFile); err == nil && strings.TrimSpace(string(b)) != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("serve exited %d\n%s", code, out.String())
		}
	case <-time.After(within):
		t.Fatal("serve did not stop")
	}
	return logs.String()
}

// TestServeStartupWarnsAboutSigning: one Warn when signing is configured
// and the vouched install has no verifying .sig (with the config sign
// remedy); the keygen Warn for a private key without its public file;
// neither line when signing is off or the install is signed. serve starts
// in every case and writes nothing under the store.
func TestServeStartupWarnsAboutSigning(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, _, _ := signedRoot(t)
	hash := readPointer(t, ctl)
	before := mustReadDirNames(t, installedStore(ctl))
	if logs := startServeOnce(t, ctl); strings.Contains(logs, "not signed") || strings.Contains(logs, "config keygen") {
		t.Fatalf("signed: no warning:\n%s", logs)
	}
	if err := os.Remove(config.SignaturePath(installedStore(ctl), hash)); err != nil {
		t.Fatal(err)
	}
	logs := startServeOnce(t, ctl)
	if !strings.Contains(logs, "level=WARN") || !strings.Contains(logs, "installed configuration is not signed; every pull will answer 503 until signed; run: agenthof config sign --control-log "+ctl) {
		t.Fatalf("not signed:\n%s", logs)
	}
	if err := os.Remove(signingPubPath(ctl)); err != nil {
		t.Fatal(err)
	}
	logs = startServeOnce(t, ctl)
	if !strings.Contains(logs, "level=WARN") || !strings.Contains(logs, signingKeyPath(ctl)+" present without "+signingPubPath(ctl)+"; run: agenthof config keygen --control-log "+ctl) {
		t.Fatalf("state C:\n%s", logs)
	}
	if err := os.Remove(signingKeyPath(ctl)); err != nil {
		t.Fatal(err)
	}
	if logs := startServeOnce(t, ctl); strings.Contains(logs, "not signed") || strings.Contains(logs, "config keygen") {
		t.Fatalf("unsigned host: no warning:\n%s", logs)
	}
	after := mustReadDirNames(t, installedStore(ctl))
	if len(after) != len(before)-1 { // the .sig we removed; serve wrote nothing
		t.Fatalf("serve must write nothing under the store: %v → %v", before, after)
	}
}

// TestServeStartupWarnsAboutAnUnreadableSignatureButNotARace: the config sign
// remedy is for a sign gap only. A .sig at a version above the vouched install
// is a read racing a re-apply (the pull retries to 200), so serve starts
// silently. A .sig that cannot be read at all is a store fault the remedy
// cannot fix, so serve warns about it — but without offering config sign.
func TestServeStartupWarnsAboutAnUnreadableSignatureButNotARace(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, _, keyID := signedRoot(t)
	hash := readPointer(t, ctl)
	sigPath := config.SignaturePath(installedStore(ctl), hash)

	at := controlEvents(t, ctl)[0].Time.UTC() // the vouched install is seq 1
	newer, err := config.SignaturePayload(hash, controlLogID(t, ctl), 2, at, keyID)
	if err != nil {
		t.Fatal(err)
	}
	writeSigAt(t, ctl, newer, config.Sign(hostPriv(t, ctl), newer))
	if logs := startServeOnce(t, ctl); strings.Contains(logs, "not signed") || strings.Contains(logs, "config sign") || strings.Contains(logs, "level=WARN") {
		t.Fatalf("raced signature: no warning:\n%s", logs)
	}

	if err := os.Remove(sigPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(sigPath, 0o700); err != nil { // reading it fails with something other than not-exist
		t.Fatal(err)
	}
	logs := startServeOnce(t, ctl)
	if !strings.Contains(logs, "level=WARN") || !strings.Contains(logs, "unreadable") {
		t.Fatalf("unreadable signature: want a store-fault warning:\n%s", logs)
	}
	if strings.Contains(logs, "config sign") {
		t.Fatalf("unreadable signature: must not offer the config sign remedy:\n%s", logs)
	}
}

// TestServeStartupWarnsWhenThePinnedKeyDoesNotVerify: with a key
// pinned and the .sig removed, serve starts, logs ONE Warn carrying the
// reason, creates no verify.floor (verifyOnly), and sizes the shutdown
// deadline from the LOADED configuration's step timeout — 90s here, not the
// 5m default, which is what proves cfg was kept. With a valid pin: no new
// Warn, still no floor at startup.
func TestServeStartupWarnsWhenThePinnedKeyDoesNotVerify(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	keygenAt(t, ctl)
	root := pullSample(t)
	writeFileIn(t, root, "gateway.yaml", "models:\n  fast:\n    endpoint: https://example.test/v1\n    model: m\n    api_key_env: K\nstep_timeout: 90s\n")
	applyAs(t, root, ctl)
	pinHostKey(t, ctl)
	hash := readPointer(t, ctl)

	logs := startServeOnce(t, ctl)
	if strings.Contains(logs, "pinned key") || strings.Contains(logs, "level=WARN") {
		t.Fatalf("valid pin: no warning:\n%s", logs)
	}
	if _, err := os.Stat(verifyFloorPath(ctl)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("startup is verifyOnly: no floor: %v", err)
	}

	if err := os.Remove(config.SignaturePath(installedStore(ctl), hash)); err != nil {
		t.Fatal(err)
	}
	logs = startServeOnce(t, ctl)
	if !strings.Contains(logs, "level=WARN") || !strings.Contains(logs, "installed configuration does not verify against the pinned key; every run will be refused until it does") ||
		!strings.Contains(logs, "configuration not verified: unsigned: no signature file for "+hash) || !strings.Contains(logs, "pinned_key="+verifyPubPath(ctl)) {
		t.Fatalf("unsigned under a pin:\n%s", logs)
	}
	if strings.Count(logs, "level=WARN") != 1 {
		t.Fatalf("exactly one Warn:\n%s", logs)
	}
	if !strings.Contains(logs, "shutdown_timeout=1m30s") {
		t.Fatalf("the loaded configuration's step timeout is the deadline, not the default:\n%s", logs)
	}
	if _, err := os.Stat(verifyFloorPath(ctl)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("startup writes no floor even when it would pass: %v", err)
	}
	if !strings.Contains(logs, "serve started") {
		t.Fatalf("serve starts in every case:\n%s", logs)
	}
}

// TestServeStartupWarnsWhenTheInstallIsNotOnRecord: unpinned, a hand-aimed
// pointer → serve starts, logs exactly one Warn with the not-on-record line
// and the reason, names NO key, keeps the loaded configuration's step timeout
// as the shutdown deadline; a damaged ledger → one Warn with the
// cannot-be-vouched line (never "not on record", never a key); a vouched
// root → zero Warn. Nothing is written under the store or beside the ledger
// except installed.lock.
func TestServeStartupWarnsWhenTheInstallIsNotOnRecord(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	writeFileIn(t, root, "gateway.yaml", "models:\n  fast:\n    endpoint: https://example.test/v1\n    model: m\n    api_key_env: K\nstep_timeout: 90s\n")
	ctl := applied(t, root)
	hashA := readPointer(t, ctl)
	if logs := startServeOnce(t, ctl); strings.Contains(logs, "level=WARN") {
		t.Fatalf("vouched root: no warning:\n%s", logs)
	}

	writeFileIn(t, root, "agents/planner.yaml", "name: planner\nmodel: fast\ninstruction: plan harder\noutput: plan\nendpoint: http://127.0.0.1:1\n")
	applyAs(t, root, ctl)
	hashB := readPointer(t, ctl)
	repointTo(t, ctl, hashA)
	logs := startServeOnce(t, ctl)
	if !strings.Contains(logs, "level=WARN") || !strings.Contains(logs, "installed configuration is not on record in the control ledger; every run will be refused until it is") ||
		!strings.Contains(logs, "configuration not on record: last recorded install is "+hashB+" (apply); re-apply (for a torn ledger, audit repair control first)") {
		t.Fatalf("not on record:\n%s", logs)
	}
	if strings.Contains(logs, "pinned_key=") || strings.Contains(logs, "pinned key") {
		t.Fatalf("no key is pinned, so none is named:\n%s", logs)
	}
	if strings.Count(logs, "level=WARN") != 1 {
		t.Fatalf("exactly one Warn:\n%s", logs)
	}
	if !strings.Contains(logs, "shutdown_timeout=1m30s") || !strings.Contains(logs, "serve started") {
		t.Fatalf("cfg is kept for the deadline and serve starts:\n%s", logs)
	}
	if _, err := os.Stat(verifyFloorPath(ctl)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("unpinned startup writes no floor: %v", err)
	}

	// damaged ledger: the neutral line, the reason carries the repair hint.
	repointTo(t, ctl, hashB)
	appendFragment(t, ctl)
	logs = startServeOnce(t, ctl)
	if !strings.Contains(logs, "level=WARN") || !strings.Contains(logs, "installed configuration cannot be vouched for; every run will be refused until the cause is fixed") ||
		!strings.Contains(logs, "configuration not verifiable: control ledger damaged; run: agenthof audit repair control --control-log "+ctl) {
		t.Fatalf("damaged:\n%s", logs)
	}
	if strings.Contains(logs, "not on record") || strings.Contains(logs, "pinned_key=") {
		t.Fatalf("a damaged ledger is not a not-on-record verdict and names no key:\n%s", logs)
	}
	if strings.Count(logs, "level=WARN") != 1 || !strings.Contains(logs, "serve started") {
		t.Fatalf("one Warn, serve starts:\n%s", logs)
	}
}
