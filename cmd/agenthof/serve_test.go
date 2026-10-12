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

func startServeOnce(t *testing.T, ctl string) string {
	t.Helper()
	return startServeOnceWithin(t, ctl, 5*time.Second)
}

// startServeOnceWithin is startServeOnce with a chosen deadline for the
// address file — for a startup that must first wait out lockTimeout.
func startServeOnceWithin(t *testing.T, ctl string, within time.Duration) string {
	t.Helper()
	t.Chdir(t.TempDir())
	t.Setenv("AGENTHOF_OIDC_ISSUER", "https://idp.test")
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

// TestServeStartupWarnsWhenThePinnedKeyDoesNotVerify (§9, S2): with a key
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
		t.Fatalf("S2: the loaded configuration's step timeout is the deadline, not the default:\n%s", logs)
	}
	if _, err := os.Stat(verifyFloorPath(ctl)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("startup writes no floor even when it would pass: %v", err)
	}
	if !strings.Contains(logs, "serve started") {
		t.Fatalf("serve starts in every case:\n%s", logs)
	}
}
