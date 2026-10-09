package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/ledger"
	"github.com/agenthof/agenthof/internal/obs"
	"github.com/agenthof/agenthof/internal/serve"
)

// signedRoot is keygen + apply of pullSample: state D with a valid .sig.
func signedRoot(t *testing.T) (ctl, root, keyID string) {
	t.Helper()
	ctl = filepath.Join(t.TempDir(), "control.jsonl")
	keyID, _ = keygenAt(t, ctl)
	root = pullSample(t)
	applyAs(t, root, ctl)
	return ctl, root, keyID
}

// writeSigAt writes a .sig at the CURRENT pointer's path for an arbitrary
// payload and signature string — the hand-written files of the table below.
func writeSigAt(t *testing.T, ctl string, payload []byte, sig string) {
	t.Helper()
	store := installedStore(ctl)
	if err := config.WriteSignatureFile(store, readPointer(t, ctl), payload, sig); err != nil {
		t.Fatal(err)
	}
}

// hostPriv is the private key beside ctl.
func hostPriv(t *testing.T, ctl string) ed25519.PrivateKey {
	t.Helper()
	priv, err := config.ParseSigningKey(mustRead(t, signingKeyPath(ctl)))
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

// TestPullConfigSignatureOutcomeTable: the vouching extension, one row per
// state of the key files and of the .sig.
func TestPullConfigSignatureOutcomeTable(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	// A: pulled, no signature.
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	applyAs(t, pullSample(t), ctl)
	if out := pullAPI(t, ctl, edgeInvoker); out.Kind != pulled || out.Snapshot.Signature != nil {
		t.Fatalf("A: %d %+v", out.Kind, out.Snapshot.Signature)
	}

	// D with a valid .sig: pulled, the signature populated and verifying for the served fields.
	ctl, root, id := signedRoot(t)
	hash := readPointer(t, ctl)
	logID := controlLogID(t, ctl)
	pub := signingPub(t, ctl)
	out := pullAPI(t, ctl, edgeInvoker)
	if out.Kind != pulled || out.Snapshot.Signature == nil {
		t.Fatalf("D: %d %v", out.Kind, out.Err)
	}
	sig := out.Snapshot.Signature
	if sig.Format != config.SignatureFormatV1 || sig.LogID != logID || sig.KeyID != id {
		t.Fatalf("%+v", sig)
	}
	if out.Snapshot.InstalledAt.Location() != time.UTC {
		t.Fatalf("installed_at is served in UTC by construction: %v", out.Snapshot.InstalledAt.Location())
	}
	payload, err := config.SignaturePayload(hash, logID, out.Snapshot.Version, out.Snapshot.InstalledAt, id)
	if err != nil || !config.Verify(pub, payload, sig.Sig) {
		t.Fatalf("the served signature must verify for the served fields: %v", err)
	}
	valid := mustRead(t, config.SignaturePath(installedStore(ctl), hash))

	// D with no .sig.
	if err := os.Remove(config.SignaturePath(installedStore(ctl), hash)); err != nil {
		t.Fatal(err)
	}
	if out := pullAPI(t, ctl, edgeInvoker); out.Kind != pullNotSigned || !errors.Is(out.Err, errNotSigned) || !strings.Contains(out.Err.Error(), "no signature file") {
		t.Fatalf("no .sig: %d %v", out.Kind, out.Err)
	}

	// D with a stale .sig: an identical re-apply (seq 2) rewrote it; restore the seq-1 file.
	applyAs(t, root, ctl)
	if err := os.WriteFile(config.SignaturePath(installedStore(ctl), hash), valid, 0o600); err != nil {
		t.Fatal(err)
	}
	out = pullAPI(t, ctl, edgeInvoker)
	if out.Kind != pullNotSigned || errors.Is(out.Err, errSignatureNewer) || !strings.Contains(out.Err.Error(), "signature is for version 1, installed is 2") {
		t.Fatalf("stale: %d %v", out.Kind, out.Err)
	}

	// D with a .sig at version N+1 against a ledger at N: the benign read race.
	// at is the vouched install's time (seq 2), normalized exactly as the pull does.
	priv := hostPriv(t, ctl)
	at := controlEvents(t, ctl)[1].Time.UTC()
	newer, _ := config.SignaturePayload(hash, logID, 3, at, id)
	writeSigAt(t, ctl, newer, config.Sign(priv, newer))
	out = pullAPI(t, ctl, edgeInvoker)
	if out.Kind != pullNotSigned || !errors.Is(out.Err, errSignatureNewer) {
		t.Fatalf("raced: %d %v", out.Kind, out.Err)
	}

	// D with a .sig by another key: named by id, before any verify.
	foreign, _ := config.SignaturePayload(hash, logID, 2, at, goldenKeyID)
	writeSigAt(t, ctl, foreign, config.Sign(priv, foreign))
	out = pullAPI(t, ctl, edgeInvoker)
	if out.Kind != pullNotSigned || !strings.Contains(out.Err.Error(), "signature is by key "+goldenKeyID+"; configured key is "+id) {
		t.Fatalf("other key: %d %v", out.Kind, out.Err)
	}

	// D with <H1>.sig carrying an H2 payload.
	other, _ := config.SignaturePayload("sha256:"+strings.Repeat("0", 64), logID, 2, at, id)
	writeSigAt(t, ctl, other, config.Sign(priv, other))
	if out := pullAPI(t, ctl, edgeInvoker); out.Kind != pullNotSigned || !strings.Contains(out.Err.Error(), "signature is for hash sha256:0000") {
		t.Fatalf("foreign hash: %d %v", out.Kind, out.Err)
	}

	// D with a .sig whose log_id differs: another control root's signature.
	otherLedger, _ := config.SignaturePayload(hash, strings.Repeat("f", 32), 2, at, id)
	writeSigAt(t, ctl, otherLedger, config.Sign(priv, otherLedger))
	if out := pullAPI(t, ctl, edgeInvoker); out.Kind != pullNotSigned || !strings.Contains(out.Err.Error(), "signature is for log_id ffff") {
		t.Fatalf("foreign log_id: %d %v", out.Kind, out.Err)
	}

	// D with a foreign log_id AND a version above the vouched seq: foreign,
	// not the read race — the race is only the same hash and ledger, newer.
	newerForeign, _ := config.SignaturePayload(hash, strings.Repeat("f", 32), 3, at, id)
	writeSigAt(t, ctl, newerForeign, config.Sign(priv, newerForeign))
	if out := pullAPI(t, ctl, edgeInvoker); out.Kind != pullNotSigned || errors.Is(out.Err, errSignatureNewer) || !strings.Contains(out.Err.Error(), "signature is for log_id ffff") {
		t.Fatalf("foreign log_id, newer version: %d %v", out.Kind, out.Err)
	}

	// D with a good payload and a bad signature.
	good, _ := config.SignaturePayload(hash, logID, 2, at, id)
	writeSigAt(t, ctl, good, config.Sign(priv, other))
	if out := pullAPI(t, ctl, edgeInvoker); out.Kind != pullNotSigned || !strings.Contains(out.Err.Error(), "does not verify") {
		t.Fatalf("bad signature: %d %v", out.Kind, out.Err)
	}

	// D with "version: 07": malformed, named by line, never "newer".
	sigPath := config.SignaturePath(installedStore(ctl), hash)
	writeSigAt(t, ctl, good, config.Sign(priv, good))
	edited := bytes.Replace(mustRead(t, sigPath), []byte("version: 2\n"), []byte("version: 02\n"), 1)
	if err := os.WriteFile(sigPath, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	if out := pullAPI(t, ctl, edgeInvoker); out.Kind != pullNotSigned || errors.Is(out.Err, errSignatureNewer) || !strings.Contains(out.Err.Error(), "line 4") {
		t.Fatalf("version 02: %d %v", out.Kind, out.Err)
	}

	// D with a v2-format file: named as format, before key or version.
	v2 := bytes.Replace(mustRead(t, sigPath), []byte("agenthof-config-signature/v1\n"), []byte("agenthof-config-signature/v2\n"), 1)
	if err := os.WriteFile(sigPath, v2, 0o600); err != nil {
		t.Fatal(err)
	}
	if out := pullAPI(t, ctl, edgeInvoker); out.Kind != pullNotSigned || !strings.Contains(out.Err.Error(), "unsupported signature format") || strings.Contains(out.Err.Error(), "key") {
		t.Fatalf("v2: %d %v", out.Kind, out.Err)
	}

	// Back to valid for the key-file rows.
	writeSigAt(t, ctl, good, config.Sign(priv, good))
	if out := pullAPI(t, ctl, edgeInvoker); out.Kind != pulled {
		t.Fatalf("restored: %d %v", out.Kind, out.Err)
	}

	// B: the private key unreadable, then gone — the pull never opens it.
	if err := os.Chmod(signingKeyPath(ctl), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(signingKeyPath(ctl), 0o600) })
	if out := pullAPI(t, ctl, edgeInvoker); out.Kind != pulled || out.Snapshot.Signature == nil {
		t.Fatalf("B unreadable key: %d %v", out.Kind, out.Err)
	}
	_ = os.Chmod(signingKeyPath(ctl), 0o600)
	keyPEM := mustRead(t, signingKeyPath(ctl))
	if err := os.Remove(signingKeyPath(ctl)); err != nil {
		t.Fatal(err)
	}
	if out := pullAPI(t, ctl, edgeInvoker); out.Kind != pulled || out.Snapshot.Signature == nil {
		t.Fatalf("B: %d %v", out.Kind, out.Err)
	}

	// Both removed: the opt-out — an unsigned 200.
	pubPEM := mustRead(t, signingPubPath(ctl))
	if err := os.Remove(signingPubPath(ctl)); err != nil {
		t.Fatal(err)
	}
	if out := pullAPI(t, ctl, edgeInvoker); out.Kind != pulled || out.Snapshot.Signature != nil {
		t.Fatalf("both removed: %d %v %+v", out.Kind, out.Err, out.Snapshot.Signature)
	}

	// C: the private key alone — store unusable, the keygen remedy in the cause.
	if err := os.WriteFile(signingKeyPath(ctl), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if out := pullAPI(t, ctl, edgeInvoker); out.Kind != pullStoreUnusable || !strings.Contains(out.Err.Error(), "config keygen --control-log "+ctl) {
		t.Fatalf("C: %d %v", out.Kind, out.Err)
	}

	// D with a corrupt signing.pub: store unusable, never a silent downgrade.
	if err := os.WriteFile(signingPubPath(ctl), []byte("junk\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out := pullAPI(t, ctl, edgeInvoker); out.Kind != pullStoreUnusable || !strings.Contains(out.Err.Error(), "no PEM block") {
		t.Fatalf("corrupt pub: %d %v", out.Kind, out.Err)
	}
	if err := os.WriteFile(signingPubPath(ctl), pubPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	// D with no ledger file: not on record — the signature step never runs.
	if err := os.Remove(ctl); err != nil {
		t.Fatal(err)
	}
	if out := pullAPI(t, ctl, edgeInvoker); out.Kind != pullNotRecorded {
		t.Fatalf("no ledger: %d %v", out.Kind, out.Err)
	}
}

// TestPullConfigGenesisWithoutLogIDIsLedgerDamaged: a chain-valid ledger
// whose genesis carries no log_id was not written by this program; with
// signing configured the pull fails closed as ledger damage, never as
// "not signed".
func TestPullConfigGenesisWithoutLogIDIsLedgerDamaged(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	keygenAt(t, ctl)
	hash := installByHandWithPointer(t, ctl, map[string]string{"roles/ops.yaml": "name: platform-admin\nallowed_groups: [platform-eng]\ncontrol: [apply]\n"})
	c, err := ledger.Open(ctl, ledger.Locked)
	if err != nil {
		t.Fatal(err)
	}
	line := `{"v":"control/1","seq":1,"time":"2026-10-09T02:12:01Z","action":"apply","outcome":"success","invoker":{"subject":"dana@example.com","issuer":"local","method":"asserted"},"witness":{"os_user":"dana","hostname":"h"},"config_hash":"` + hash + `","prev":""}`
	if err := c.Append([]byte(line)); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	out := pullAPI(t, ctl, opsInvoker)
	if out.Kind != pullLedgerDamaged || !strings.Contains(out.Err.Error(), "no log_id") {
		t.Fatalf("%d %v", out.Kind, out.Err)
	}
	// Unsigned, the same ledger serves: log_id is read only when signing is configured.
	for _, p := range []string{signingKeyPath(ctl), signingPubPath(ctl)} {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
	if out := pullAPI(t, ctl, opsInvoker); out.Kind != pulled {
		t.Fatalf("unsigned: %d %v", out.Kind, out.Err)
	}
}

// TestPullConfigSignedAvailabilityInvariant: with signing configured,
// pulled ⟺ the chain verifies ∧ the pointer matches ∧ the .sig verifies;
// each conjunct removed yields its own answer.
func TestPullConfigSignedAvailabilityInvariant(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, root, _ := signedRoot(t)
	hash := readPointer(t, ctl)
	if out := pullAPI(t, ctl, opsInvoker); out.Kind != pulled {
		t.Fatalf("all three hold: %d", out.Kind)
	}
	sigPath := config.SignaturePath(installedStore(ctl), hash)
	valid := mustRead(t, sigPath)
	if err := os.Remove(sigPath); err != nil {
		t.Fatal(err)
	}
	if out := pullAPI(t, ctl, opsInvoker); out.Kind != pullNotSigned {
		t.Fatalf("no .sig: %d", out.Kind)
	}
	if err := os.WriteFile(sigPath, valid, 0o600); err != nil {
		t.Fatal(err)
	}
	writeFileIn(t, root, "agents/planner.yaml", "name: planner\nmodel: fast\ninstruction: plan harder\noutput: plan\nendpoint: http://127.0.0.1:1\n")
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "after_install_before_append")
	_, _ = applyCode(t, root, ctl)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "")
	if out := pullAPI(t, ctl, opsInvoker); out.Kind != pullNotRecorded {
		t.Fatalf("pointer moved, not recorded: %d (the signature step runs after vouching)", out.Kind)
	}
	applyAs(t, root, ctl)
	if out := pullAPI(t, ctl, opsInvoker); out.Kind != pulled || out.Snapshot.Version != 2 {
		t.Fatalf("re-apply signs and vouches: %d %+v", out.Kind, out.Snapshot)
	}
	appendFragment(t, ctl)
	if out := pullAPI(t, ctl, opsInvoker); out.Kind != pullLedgerDamaged {
		t.Fatalf("torn: %d", out.Kind)
	}
}

// TestConfigHostPullLogsTheSignGap: the host logs a genuine gap at Warn with
// the config sign hint, the benign read race at Info with no hint, and a
// broken key state at Error with the keygen hint.
func TestConfigHostPullLogsTheSignGap(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, _, id := signedRoot(t)
	logs := &bytes.Buffer{}
	h := &configHost{controlLog: ctl, allowBootstrap: true, logger: obs.New(logs, slog.LevelDebug, obs.FormatText)}
	hash := readPointer(t, ctl)
	if res := h.Pull(apiInvoker); res.Status != serve.PullOK || res.Snapshot.Signature == nil {
		t.Fatalf("%+v", res)
	}
	if err := os.Remove(config.SignaturePath(installedStore(ctl), hash)); err != nil {
		t.Fatal(err)
	}
	if res := h.Pull(apiInvoker); res.Status != serve.PullNotSigned || res.Snapshot.Hash != "" {
		t.Fatalf("%+v", res)
	}
	if l := logs.String(); !strings.Contains(l, "level=WARN") || !strings.Contains(l, "config sign --control-log "+ctl) {
		t.Fatalf("a genuine gap is a Warn with the remedy:\n%s", l)
	}
	logs.Reset()
	priv := hostPriv(t, ctl)
	newer, _ := config.SignaturePayload(hash, controlLogID(t, ctl), 2, controlEvents(t, ctl)[0].Time.UTC(), id)
	writeSigAt(t, ctl, newer, config.Sign(priv, newer))
	if res := h.Pull(apiInvoker); res.Status != serve.PullNotSigned {
		t.Fatalf("%+v", res)
	}
	if l := logs.String(); !strings.Contains(l, "level=INFO") || strings.Contains(l, "level=WARN") || strings.Contains(l, "config sign --control-log") {
		t.Fatalf("the read race is an Info with no remedy:\n%s", l)
	}
	logs.Reset()
	if err := os.Remove(signingPubPath(ctl)); err != nil {
		t.Fatal(err)
	}
	if res := h.Pull(apiInvoker); res.Status != serve.PullStoreUnusable {
		t.Fatalf("%+v", res)
	}
	if l := logs.String(); !strings.Contains(l, "level=ERROR") || !strings.Contains(l, "config keygen --control-log "+ctl) {
		t.Fatalf("state C is logged with the keygen remedy:\n%s", l)
	}
	if len(controlEvents(t, ctl)) != 1 {
		t.Fatal("no pull records")
	}
}

// staticAuth answers every bearer with one invoker: the handler and the
// encoder are the real ones; only the identity provider is stubbed.
type staticAuth struct{ inv identity.Invoker }

func (a staticAuth) Authenticate(context.Context, string) (identity.Invoker, error) {
	return a.inv, nil
}

// TestServedSignatureVerifiesFromTheWireBytes is the edge's contract, end to
// end, from the bytes the real route serves: the payload is rebuilt from
// the JSON strings and the version number's source text — never from Go
// values — and verified under the PEM config keygen printed. Format is
// checked before key id, key id before any verify.
func TestServedSignatureVerifiesFromTheWireBytes(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	_, keygenOut := keygenAt(t, ctl)
	applyAs(t, pullSample(t), ctl)
	pemStart := strings.Index(keygenOut, "-----BEGIN PUBLIC KEY-----")
	pemEnd := strings.Index(keygenOut, "-----END PUBLIC KEY-----") + len("-----END PUBLIC KEY-----\n")
	pinned, err := config.ParseSigningPub([]byte(keygenOut[pemStart:pemEnd]))
	if err != nil {
		t.Fatal(err)
	}
	logger := obs.New(io.Discard, slog.LevelDebug, obs.FormatText)
	srv, err := serve.New(serve.Config{
		Auth: staticAuth{opsInvoker}, Host: &runHost{controlLog: ctl, logger: logger},
		Config: &configHost{controlLog: ctl, logger: logger}, LogDir: t.TempDir(), ControlLog: ctl,
		MaxConcurrentRuns: 1, ServerHost: "127.0.0.1:0", Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	for _, path := range []string{"/v1/config/hash", "/v1/config"} {
		req, _ := http.NewRequest(http.MethodGet, hs.URL+path, nil)
		req.Header.Set("Authorization", "Bearer x")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d %s", path, resp.StatusCode, body)
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(body, &raw); err != nil {
			t.Fatal(err)
		}
		str := func(m map[string]json.RawMessage, k string) string {
			var s string
			if err := json.Unmarshal(m[k], &s); err != nil {
				t.Fatalf("%s.%s: %v", path, k, err)
			}
			return s
		}
		var sig map[string]json.RawMessage
		if err := json.Unmarshal(raw["signature"], &sig); err != nil {
			t.Fatalf("%s: no signature object: %s", path, body)
		}
		if str(sig, "format") != "agenthof-config-signature/v1" {
			t.Fatalf("%s: unsupported signature format %s", path, sig["format"])
		}
		if str(sig, "key_id") != config.KeyID(pinned) {
			t.Fatalf("%s: unknown key %s", path, sig["key_id"])
		}
		payload := "agenthof-config-signature/v1\n" +
			"hash: " + str(raw, "hash") + "\n" +
			"log_id: " + str(sig, "log_id") + "\n" +
			"version: " + string(raw["version"]) + "\n" +
			"installed_at: " + str(raw, "installed_at") + "\n" +
			"key_id: " + str(sig, "key_id") + "\n"
		if !config.Verify(pinned, []byte(payload), str(sig, "sig")) {
			t.Fatalf("%s: bad signature over\n%q", path, payload)
		}
		if path == "/v1/config/hash" && bytes.Contains(body, []byte(`"files"`)) {
			t.Fatal("the hash route carries no files")
		}
	}
}
