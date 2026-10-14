package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/anchor"
	"github.com/agenthof/agenthof/internal/anchor/anchortest"
	"github.com/agenthof/agenthof/internal/broker"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/ledger"
)

// TestAnchorProofCapsAgree: the record cap and the backend cap are one number
// (control does not import anchor; this is where both are in scope).
func TestAnchorProofCapsAgree(t *testing.T) {
	if anchor.MaxProofLen != control.MaxAnchorProofLen {
		t.Fatalf("anchor.MaxProofLen %d != control.MaxAnchorProofLen %d", anchor.MaxProofLen, control.MaxAnchorProofLen)
	}
}

func writePEM(t *testing.T, dir, name string, pub any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestAnchorKeyPathMirrorsPinnedKeyPath: --anchor-key given IS the pin whether
// or not the file exists (it fails closed at load); absent, anchor.pub beside
// the ledger is stat'ed — present ⇒ pinned, absent ⇒ unpinned.
func TestAnchorKeyPathMirrorsPinnedKeyPath(t *testing.T) {
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	if got := anchorPubPath(ctl); got != filepath.Join(filepath.Dir(ctl), "anchor.pub") {
		t.Fatalf("anchorPubPath = %q", got)
	}
	pinned, path, err := anchorKeyPath(ctl, "")
	if err != nil || pinned || path != anchorPubPath(ctl) {
		t.Fatalf("absent: %v %v %q", pinned, err, path)
	}
	pinned, path, err = anchorKeyPath(ctl, "/nope/key.pub")
	if err != nil || !pinned || path != "/nope/key.pub" {
		t.Fatalf("flag: %v %v %q", pinned, err, path)
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, filepath.Dir(ctl), "anchor.pub", &priv.PublicKey)
	pinned, _, err = anchorKeyPath(ctl, "")
	if err != nil || !pinned {
		t.Fatalf("present: %v %v", pinned, err)
	}
	pub, err := pinnedLogKey(ctl, "")
	if err != nil || !pub.Equal(&priv.PublicKey) {
		t.Fatalf("pinnedLogKey: %v", err)
	}
	if _, err := pinnedLogKey(ctl, "/nope/key.pub"); err == nil || !strings.HasPrefix(err.Error(), "pinned log key /nope/key.pub: ") {
		t.Fatalf("missing --anchor-key must fail closed: %v", err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ed := writePEM(t, t.TempDir(), "ed.pub", edPub)
	if _, err := pinnedLogKey(ctl, ed); err == nil || !strings.Contains(err.Error(), "must be ECDSA") || !strings.HasPrefix(err.Error(), "pinned log key "+ed+": ") {
		t.Fatalf("ed25519 pin: %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(ctl), "verify.pub")); !os.IsNotExist(err) {
		t.Fatal("anchor.pub and verify.pub are different files")
	}
}

// TestAnchorCredentialRefMapsFieldForField: the first consumer of
// BackendCredential — every env NAME and coordinate lands on the broker ref,
// ResourceID is fixed, and no credential yields no bearer.
func TestAnchorCredentialRefMapsFieldForField(t *testing.T) {
	c := config.BackendCredential{CredentialSource: "static_env", TokenEnv: "T", GrantType: "client_credentials", ClientAuth: "client_secret_basic",
		Issuer: "https://as.example", TokenEndpoint: "https://as.example/token", ClientIDEnv: "ID", ClientSecretEnv: "SECRET", Scope: "rekor.write", Audience: "rekor"}
	want := broker.CredentialRef{ResourceID: "integrity/anchor_backend", Source: "static_env", Grant: "client_credentials", ClientAuth: "client_secret_basic",
		Issuer: "https://as.example", TokenURL: "https://as.example/token", Scope: "rekor.write", Audience: "rekor", TokenEnv: "T", ClientIDEnv: "ID", ClientSecretEnv: "SECRET"}
	if got := anchorCredentialRef(c); got != want {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	if anchorBearer(config.BackendCredential{}, anchorHTTPClient) != nil {
		t.Fatal("no credential → nil bearer (anonymous)")
	}
	t.Setenv("REKOR_TOKEN", "tok-1")
	b := anchorBearer(config.BackendCredential{TokenEnv: "REKOR_TOKEN"}, anchorHTTPClient)
	if tok, err := b(context.Background()); err != nil || tok != "tok-1" {
		t.Fatalf("direct bearer: %q %v", tok, err)
	}
	t.Setenv("ANCHOR_ID", "")
	b = anchorBearer(config.BackendCredential{GrantType: "client_credentials", ClientAuth: "client_secret_basic", TokenEndpoint: "http://127.0.0.1:9/token", ClientIDEnv: "ANCHOR_ID", ClientSecretEnv: "ANCHOR_SECRET"}, anchorHTTPClient)
	if _, err := b(context.Background()); err == nil || err.Error() != "broker: client id env ANCHOR_ID is not set" {
		t.Fatalf("client_credentials with unset env must name the env NAME only (clientcreds.go's exact text): %v", err)
	}
	b = anchorBearer(config.BackendCredential{GrantType: "token_exchange"}, anchorHTTPClient)
	if _, err := b(context.Background()); err == nil || !strings.Contains(err.Error(), "token_exchange") {
		t.Fatalf("token_exchange must be refused, not dereferenced: %v", err)
	}
}

// TestAnchorBackendForDispatchesOnKind: transparency-log → a *anchor.Rekor
// with the URL trimmed; any other kind (rfc3161 included — nothing in
// production constructs it) → "is not implemented".
func TestAnchorBackendForDispatchesOnKind(t *testing.T) {
	be, err := anchorBackendFor(backendSpec{Kind: "transparency-log", URL: "https://rekor.sigstore.dev/"})
	if err != nil || be.Kind() != "transparency-log" {
		t.Fatalf("%v %v", be, err)
	}
	if _, ok := be.(*anchor.Rekor); !ok {
		t.Fatalf("want *anchor.Rekor, got %T", be)
	}
	for _, kind := range []string{"rfc3161", "kms", ""} {
		if _, err := anchorBackendFor(backendSpec{Kind: kind, URL: "https://x.example"}); err == nil || err.Error() != "anchor backend kind "+quote(kind)+" is not implemented" {
			t.Fatalf("%q: %v", kind, err)
		}
	}
	if _, err := anchorBackendFor(backendSpec{Kind: "transparency-log", URL: "rekor.sigstore.dev"}); err == nil {
		t.Fatal("a non-absolute URL must be refused at construction")
	}
}

// TestAnchorExitCodesAndBackendSeam pins the two documented exit codes, and
// that the test seam starts out as the real dispatch.
func TestAnchorExitCodesAndBackendSeam(t *testing.T) {
	if exitAnchorMismatch != 6 || exitAnchorUnverifiable != 7 {
		t.Fatalf("anchor exit codes = %d, %d; want 6, 7", exitAnchorMismatch, exitAnchorUnverifiable)
	}
	be, err := newAnchorBackend(backendSpec{Kind: "transparency-log", URL: "https://rekor.sigstore.dev"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := be.(*anchor.Rekor); !ok {
		t.Fatalf("newAnchorBackend default: want *anchor.Rekor, got %T", be)
	}
}

func quote(s string) string { return `"` + s + `"` }

// tlogPostureFor writes a complete tlog posture naming url beside ctl.
func tlogPostureFor(t *testing.T, ctl, url string) {
	t.Helper()
	writeIntegrity(t, ctl, "anchor: tlog\nanchor_backend:\n  url: "+url+"\n")
}

// anchorSample is writeSample with the platform-admin role also granting
// anchor (the sample's own grants stop short of it). Call it before applied.
func anchorSample(t *testing.T) string {
	t.Helper()
	root := writeSample(t)
	role := "name: platform-admin\nallowed_groups: [platform-eng]\ncontrol: [apply, enable, disable, repair, provision, prune, anchor]\n"
	if err := os.WriteFile(filepath.Join(root, "roles", "ops.yaml"), []byte(role), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

// useStub routes every backend construction to one shared Stub for the test's
// life — the rfc3161 kind is otherwise unreachable, since Validate refuses it
// in a real file.
func useStub(t *testing.T) *anchortest.Stub {
	t.Helper()
	stub := anchortest.NewStub([]byte("test-secret"))
	prev := newAnchorBackend
	newAnchorBackend = func(backendSpec) (anchor.Backend, error) { return stub, nil }
	t.Cleanup(func() { newAnchorBackend = prev })
	return stub
}

// TestAuditAnchorViaStubWritesAProofCarryingRecord: through the
// newAnchorBackend override, audit anchor records a success anchor whose
// backend_kind is the backend's own kind (rfc3161), with a proof and no key
// id, and prints "log key: none".
func TestAuditAnchorViaStubWritesAProofCarryingRecord(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	useStub(t)
	ctl := applied(t, anchorSample(t))
	tlogPostureFor(t, ctl, "http://stub.invalid")
	var out bytes.Buffer
	if code := cmdAudit([]string{"anchor", "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "anchored: seq=1 sha256=") || !strings.Contains(out.String(), "log key: none (as served)") || !strings.Contains(out.String(), "index: -  integrated: ") {
		t.Fatalf("output:\n%s", out.String())
	}
	recs, _, err := ledger.ReadVerify(ctl, ledger.Locked)
	if err != nil || len(recs) != 2 {
		t.Fatalf("%v %d", err, len(recs))
	}
	d, _ := control.Decode(recs[1].Raw)
	if d.Anchor == nil || d.Anchor.BackendKind != "rfc3161" || d.Anchor.Backend != anchortest.StubBackend || d.Anchor.Proof == "" || d.Anchor.BackendKeyID != "" || d.Anchor.Seq != 1 {
		t.Fatalf("record %+v", d.Anchor)
	}
}

// TestAuditAnchorOrderBeforeNetwork: a busy ledger is exit 1 unrecorded; an
// unvouched pointer is a recorded not_on_record refusal; nothing installed is a
// recorded not_authorized refusal — and in each case the backend is never
// constructed, let alone called.
func TestAuditAnchorOrderBeforeNetwork(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	calls := 0
	prev := newAnchorBackend
	newAnchorBackend = func(backendSpec) (anchor.Backend, error) { calls++; return nil, errors.New("must not be reached") }
	t.Cleanup(func() { newAnchorBackend = prev })

	root := anchorSample(t)
	ctl := applied(t, root)
	tlogPostureFor(t, ctl, "http://127.0.0.1:9")
	crashGap(t, root, ctl) // the pointer moves, the ledger does not vouch
	var out bytes.Buffer
	if code := cmdAudit([]string{"anchor", "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 1 || !strings.Contains(out.String(), "configuration not on record") {
		t.Fatalf("unvouched: exit %d\n%s", code, out.String())
	}
	recs, _, _ := ledger.ReadVerify(ctl, ledger.Locked)
	if d, _ := control.Decode(recs[len(recs)-1].Raw); d.Action != "anchor" || d.Outcome != "refused" || d.Reason.Code != control.CodeNotOnRecord || d.Anchor != nil {
		t.Fatalf("last record %+v", d)
	}

	fresh := filepath.Join(t.TempDir(), "control.jsonl")
	tlogPostureFor(t, fresh, "http://127.0.0.1:9")
	out.Reset()
	if code := cmdAudit([]string{"anchor", "--control-log", fresh, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 1 || !strings.Contains(out.String(), msgNothingInstalled) {
		t.Fatalf("nothing installed: exit %d\n%s", code, out.String())
	}
	recs, _, _ = ledger.ReadVerify(fresh, ledger.Locked)
	if d, _ := control.Decode(recs[0].Raw); d.Action != "anchor" || d.Outcome != "refused" || d.Reason.Message != msgNothingInstalled {
		t.Fatalf("fresh root record %+v", d)
	}
	if calls != 0 {
		t.Fatalf("the backend was constructed %d times before authorization", calls)
	}
}

// TestAuditAnchorNotRecordedAfterSubmit: when the append after a successful
// submit fails (the ledger made read-only between), the command says so and
// exits 1 — the public entry exists and is harmless.
func TestAuditAnchorNotRecordedAfterSubmit(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: file permissions are not enforced")
	}
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl := applied(t, anchorSample(t))
	tlogPostureFor(t, ctl, "http://stub.invalid")
	// Make the ledger unappendable only once the head has been read: the
	// backend hook is the last thing before Append, so chmod there.
	prev := newAnchorBackend
	newAnchorBackend = func(backendSpec) (anchor.Backend, error) {
		if err := os.Chmod(ctl, 0o400); err != nil {
			t.Fatal(err)
		}
		return anchortest.NewStub([]byte("s")), nil
	}
	t.Cleanup(func() { newAnchorBackend = prev; _ = os.Chmod(ctl, 0o600) })
	var out bytes.Buffer
	code := cmdAudit([]string{"anchor", "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out)
	if code != 1 || !strings.Contains(out.String(), "audit anchor: anchored at ") || !strings.Contains(out.String(), " but NOT recorded") {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
}

func verifyControl(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := cmdAudit(append([]string{"verify", "control"}, args...), &out)
	return code, out.String()
}

// TestVerifyControlExpectHeadGrammar: anything outside
// ^([0-9]+:)?[0-9a-f]{64}$ is usage, exit 2, before the ledger is read.
func TestVerifyControlExpectHeadGrammar(t *testing.T) {
	ctl := applied(t, writeSample(t))
	for _, bad := range []string{"deadbeef", "x:y", "1:" + strings.Repeat("a", 63), "-1:" + strings.Repeat("a", 64), strings.Repeat("A", 64), "1:1:" + strings.Repeat("a", 64)} {
		code, out := verifyControl(t, "--control-log", ctl, "--expect-head", bad)
		if code != 2 || !strings.Contains(out, "--expect-head must be <hex> or <seq>:<hex> (64 lowercase hex)") || strings.Contains(out, "control head:") {
			t.Fatalf("%q: exit %d\n%s", bad, code, out)
		}
	}
}

// TestVerifyControlExpectHeadAtSeq: K:H holds now and after
// more records (the chain still reproduces it); after the tail from K is
// re-forged it is exit 4 "want H at seq K, got …"; K beyond Count is exit 4
// "but the chain has N records"; the <hex> form is unchanged.
func TestVerifyControlExpectHeadAtSeq(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	ctl := applied(t, root)
	recs, head1, err := ledger.ReadVerify(ctl, ledger.Locked)
	if err != nil || len(recs) != 1 {
		t.Fatal(err)
	}
	ref := "1:" + head1.Hash
	if code, out := verifyControl(t, "--control-log", ctl, "--expect-head", ref); code != 0 {
		t.Fatalf("fresh: exit %d\n%s", code, out)
	}
	var out bytes.Buffer
	if code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("disable: %d\n%s", code, out.String())
	}
	if code, out := verifyControl(t, "--control-log", ctl, "--expect-head", ref); code != 0 {
		t.Fatalf("after more records: exit %d\n%s", code, out)
	}
	_, head2, _ := ledger.ReadVerify(ctl, ledger.Locked)
	if code, out := verifyControl(t, "--control-log", ctl, "--expect-head", head2.Hash); code != 0 {
		t.Fatalf("hex form: exit %d\n%s", code, out)
	}
	if code, out := verifyControl(t, "--control-log", ctl, "--expect-head", "7:"+head1.Hash); code != 4 || !strings.Contains(out, "expect-head mismatch: want "+head1.Hash+" at seq 7, but the chain has 2 records") {
		t.Fatalf("beyond count: exit %d\n%s", code, out)
	}
	rewriteTail(t, ctl, 1, func(int, map[string]any) {})
	code, text := verifyControl(t, "--control-log", ctl, "--expect-head", ref)
	if code != 4 || !strings.Contains(text, "expect-head mismatch: want "+head1.Hash+" at seq 1, got ") || strings.Contains(text, "got "+head1.Hash) {
		t.Fatalf("re-forged: exit %d\n%s", code, text)
	}
}

// rewriteTail re-forges records from seq on: the witness is replaced (so the
// bytes change), mutate may edit the decoded record, prev is recomputed, so
// the chain stays valid while every head from seq on differs. The txtar
// reforge command is its twin.
func rewriteTail(t *testing.T, ctl string, from int, mutate func(seq int, m map[string]any)) {
	t.Helper()
	recs, _, err := ledger.ReadVerify(ctl, ledger.Unlocked)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	prev := ""
	for i, r := range recs {
		raw := r.Raw
		if i+1 >= from {
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatal(err)
			}
			m["prev"] = prev
			m["witness"] = map[string]any{"os_user": "forger", "hostname": "elsewhere"}
			mutate(i+1, m)
			if raw, err = json.Marshal(m); err != nil {
				t.Fatal(err)
			}
		}
		out.Write(raw)
		out.WriteByte('\n')
		sum := sha256.Sum256(raw)
		prev = hex.EncodeToString(sum[:])
	}
	if err := os.WriteFile(ctl, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestVerifyControlPrintsTaintAndExpectHeadTogether: a repaired (tainted)
// ledger with a wrong --expect-head prints BOTH the
// TAINTED line and the expect-head mismatch, and exits 3 — taint outranks the
// operator's note, but nothing is hidden.
func TestVerifyControlPrintsTaintAndExpectHeadTogether(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	ctl := applied(t, root)
	f, err := os.OpenFile(ctl, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"v":"control/1","seq":2,"partial`); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	var out bytes.Buffer
	if code := cmdAuditRepairControl([]string{"control", "--control-log", ctl, "--config", root, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("repair: %d\n%s", code, out.String())
	}
	code, text := verifyControl(t, "--control-log", ctl, "--expect-head", strings.Repeat("0", 64))
	if code != 3 || !strings.Contains(text, "control ledger TAINTED: repaired at seq 2") || !strings.Contains(text, "expect-head mismatch: want "+strings.Repeat("0", 64)+", got ") {
		t.Fatalf("exit %d\n%s", code, text)
	}
}

// anchoredViaStub applies a root whose operator role may anchor, anchors once
// through the stub, and returns the ledger path and the stub.
func anchoredViaStub(t *testing.T) (string, *anchortest.Stub) {
	t.Helper()
	stub := useStub(t)
	ctl := applied(t, anchorSample(t))
	tlogPostureFor(t, ctl, "http://stub.invalid")
	var out bytes.Buffer
	if code := cmdAudit([]string{"anchor", "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("anchor: %d\n%s", code, out.String())
	}
	return ctl, stub
}

// TestVerifyControlViaStub: the stub's record verifies offline → 0; one byte
// of its proof flipped on disk (chain recomputed) passes the structural check
// and fails the backend → 6; Fail → 7; and a kind this build does not
// construct → 7 "is not implemented", never a mismatch.
func TestVerifyControlViaStub(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, stub := anchoredViaStub(t)
	if code, out := verifyControl(t, "--control-log", ctl, "--offline"); code != 0 || !strings.Contains(out, "anchor seq 1 ") || !strings.Contains(out, ": verified (log key as served by the log") || !strings.Contains(out, "anchors: 1 (1 verified, 0 mismatch, 0 unverifiable)") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	cp, _ := os.ReadFile(ctl)
	rewriteTail(t, ctl, 2, func(seq int, m map[string]any) {
		a := m["anchor"].(map[string]any)
		p := a["proof"].(string)
		a["proof"] = "A" + p[1:]
	})
	if code, out := verifyControl(t, "--control-log", ctl, "--offline"); code != exitAnchorMismatch || !strings.Contains(out, "MISMATCH — proof does not hash to the recorded ref") {
		t.Fatalf("flipped proof: exit %d\n%s", code, out)
	}
	if err := os.WriteFile(ctl, cp, 0o600); err != nil {
		t.Fatal(err)
	}
	stub.Fail()
	if code, out := verifyControl(t, "--control-log", ctl, "--offline"); code != exitAnchorUnverifiable || !strings.Contains(out, "unverifiable — stub: unavailable") {
		t.Fatalf("Fail: exit %d\n%s", code, out)
	}
	prev := newAnchorBackend
	newAnchorBackend = anchorBackendFor // production dispatch: rfc3161 is not implemented
	t.Cleanup(func() { newAnchorBackend = prev })
	if code, out := verifyControl(t, "--control-log", ctl, "--offline"); code != exitAnchorUnverifiable || !strings.Contains(out, `unverifiable — anchor backend kind "rfc3161" is not implemented`) {
		t.Fatalf("not implemented: exit %d\n%s", code, out)
	}
}

// TestVerifyControlComputesAllThenDecides: tainted + good anchor → 3 with the
// anchor line printed; tainted + forged anchor → 6 with the TAINTED line
// printed; tainted + wrong --expect-head + forged anchor → 6; unverifiable +
// pointer moved → 5; unverifiable + wrong --expect-head → 4; unverifiable
// alone → 7.
func TestVerifyControlComputesAllThenDecides(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, stub := anchoredViaStub(t)
	// Tear and repair: the ledger is now tainted (repair at seq 3).
	f, err := os.OpenFile(ctl, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{"v":"control/1","seq":3,"partial`)
	_ = f.Close()
	var out bytes.Buffer
	if code := cmdAuditRepairControl([]string{"control", "--control-log", ctl, "--config", writeSample(t), "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("repair: %d\n%s", code, out.String())
	}
	code, text := verifyControl(t, "--control-log", ctl, "--offline")
	if code != 3 || !strings.Contains(text, "TAINTED") || !strings.Contains(text, "anchor seq 1 ") || !strings.Contains(text, ": verified") {
		t.Fatalf("tainted + good: exit %d\n%s", code, text)
	}
	good, _ := os.ReadFile(ctl)
	rewriteTail(t, ctl, 2, func(seq int, m map[string]any) {
		if seq == 2 {
			m["anchor"].(map[string]any)["hash"] = strings.Repeat("ff", 32)
		}
	})
	code, text = verifyControl(t, "--control-log", ctl, "--offline")
	if code != exitAnchorMismatch || !strings.Contains(text, "TAINTED") || !strings.Contains(text, "MISMATCH — the chain does not reproduce") {
		t.Fatalf("tainted + forged: exit %d\n%s", code, text)
	}
	code, text = verifyControl(t, "--control-log", ctl, "--offline", "--expect-head", strings.Repeat("0", 64))
	if code != exitAnchorMismatch || !strings.Contains(text, "expect-head mismatch") {
		t.Fatalf("6 outranks 3 and 4: exit %d\n%s", code, text)
	}
	if err := os.WriteFile(ctl, good, 0o600); err != nil {
		t.Fatal(err)
	}

	stub.Fail() // every anchor now unverifiable
	code, text = verifyControl(t, "--control-log", ctl, "--offline")
	if code != 3 {
		t.Fatalf("3 outranks 7: exit %d\n%s", code, text)
	}
	// A fresh, untainted root for the 5 / 4 / 7 cases.
	ctl2, stub2 := anchoredViaStub(t)
	stub2.Fail()
	if code, text := verifyControl(t, "--control-log", ctl2, "--offline"); code != exitAnchorUnverifiable || !strings.Contains(text, "anchors: 1 (0 verified, 0 mismatch, 1 unverifiable)") {
		t.Fatalf("7 alone: exit %d\n%s", code, text)
	}
	if code, _ := verifyControl(t, "--control-log", ctl2, "--offline", "--expect-head", strings.Repeat("0", 64)); code != 4 {
		t.Fatalf("4 outranks 7: exit %d", code)
	}
	if err := os.WriteFile(filepath.Join(installedStore(ctl2), config.InstalledPointer), []byte("sha256:"+strings.Repeat("0", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, text := verifyControl(t, "--control-log", ctl2, "--offline"); code != exitInstalledMismatch || !strings.Contains(text, "unverifiable") {
		t.Fatalf("5 outranks 7 and still prints the anchor line: exit %d\n%s", code, text)
	}
}

// TestVerifyControlIsPostureBlind: deleting integrity.yaml, setting
// anchor: none, or writing garbage into it leaves audit verify control's
// output byte-identical.
func TestVerifyControlIsPostureBlind(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, _ := anchoredViaStub(t)
	_, want := verifyControl(t, "--control-log", ctl, "--offline")
	for name, body := range map[string]string{"none": "anchor: none\n", "garbage": "{{{"} {
		writeIntegrity(t, ctl, body)
		if _, got := verifyControl(t, "--control-log", ctl, "--offline"); got != want {
			t.Fatalf("%s: output differs\n%s\n---\n%s", name, got, want)
		}
	}
	if err := os.Remove(integrityPath(ctl)); err != nil {
		t.Fatal(err)
	}
	if _, got := verifyControl(t, "--control-log", ctl, "--offline"); got != want || strings.Contains(got, "integrity ") {
		t.Fatalf("deleted: output differs or names the posture\n%s", got)
	}
}

// TestVerifyControlOutputGolden pins the whole stdout of audit verify control
// --offline, as literals, on a stub-anchored root: clean, a flipped proof byte,
// a backend that cannot answer, the production dispatch for a kind this build
// does not construct, and a root with no anchors. Compared with ==, never
// Contains: this is the byte-identity proof the anchor verifier must keep.
func TestVerifyControlOutputGolden(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, stub := anchoredViaStub(t)
	recs, head, err := ledger.ReadVerify(ctl, ledger.Locked)
	if err != nil || len(recs) != 2 {
		t.Fatalf("%v %d", err, len(recs))
	}
	d, err := control.Decode(recs[1].Raw)
	if err != nil || d.Anchor == nil {
		t.Fatalf("%v %+v", err, d)
	}
	a := d.Anchor
	installedHash, installed, err := config.InstalledHash(installedStore(ctl))
	if err != nil || !installed {
		t.Fatalf("%v %v", err, installed)
	}
	prefix := func(headHash string) string {
		return fmt.Sprintf("control head: seq=2 sha256=%s\ninstalled config: %s — matches the last recorded install (apply)\n", headHash, installedHash)
	}
	where := fmt.Sprintf("anchor seq 1 %s → http://stub.invalid entry %s", a.Hash, a.Ref)
	if anchortest.StubBackend != "http://stub.invalid" {
		t.Fatalf("the stub's backend moved: %q", anchortest.StubBackend)
	}

	// clean: exit 0
	want := prefix(head.Hash) + where + ": verified (log key as served by the log — unpinned; pin it in anchor.pub or --anchor-key to verify independently; offline: presence not checked)\n" +
		"anchors: 1 (1 verified, 0 mismatch, 0 unverifiable)\n"
	if code, got := verifyControl(t, "--control-log", ctl, "--offline"); code != 0 || got != want {
		t.Fatalf("clean: exit %d\n--- got ---\n%s--- want ---\n%s", code, got, want)
	}

	// one byte of the proof flipped on disk, chain recomputed: exit 6
	good, _ := os.ReadFile(ctl)
	rewriteTail(t, ctl, 2, func(seq int, m map[string]any) {
		p := m["anchor"].(map[string]any)["proof"].(string)
		m["anchor"].(map[string]any)["proof"] = "A" + p[1:]
	})
	_, head2, err := ledger.ReadVerify(ctl, ledger.Locked)
	if err != nil {
		t.Fatal(err)
	}
	want = prefix(head2.Hash) + where + ": MISMATCH — proof does not hash to the recorded ref\n" +
		"anchors: 1 (0 verified, 1 mismatch, 0 unverifiable)\n"
	if code, got := verifyControl(t, "--control-log", ctl, "--offline"); code != exitAnchorMismatch || got != want {
		t.Fatalf("flipped proof: exit %d\n--- got ---\n%s--- want ---\n%s", code, got, want)
	}
	if err := os.WriteFile(ctl, good, 0o600); err != nil {
		t.Fatal(err)
	}

	// the backend cannot answer: exit 7
	stub.Fail()
	want = prefix(head.Hash) + where + ": unverifiable — stub: unavailable\n" +
		"anchors: 1 (0 verified, 0 mismatch, 1 unverifiable)\n"
	if code, got := verifyControl(t, "--control-log", ctl, "--offline"); code != exitAnchorUnverifiable || got != want {
		t.Fatalf("Fail: exit %d\n--- got ---\n%s--- want ---\n%s", code, got, want)
	}

	// production dispatch: rfc3161 is not constructed by this build: exit 7
	prev := newAnchorBackend
	newAnchorBackend = anchorBackendFor
	t.Cleanup(func() { newAnchorBackend = prev })
	want = prefix(head.Hash) + where + ": unverifiable — anchor backend kind \"rfc3161\" is not implemented\n" +
		"anchors: 1 (0 verified, 0 mismatch, 1 unverifiable)\n"
	if code, got := verifyControl(t, "--control-log", ctl, "--offline"); code != exitAnchorUnverifiable || got != want {
		t.Fatalf("not implemented: exit %d\n--- got ---\n%s--- want ---\n%s", code, got, want)
	}

	// a root with no anchors: the note, exit 0
	plain := applied(t, writeSample(t))
	_, head1, err := ledger.ReadVerify(plain, ledger.Locked)
	if err != nil {
		t.Fatal(err)
	}
	plainHash, _, err := config.InstalledHash(installedStore(plain))
	if err != nil {
		t.Fatal(err)
	}
	want = fmt.Sprintf("control head: seq=1 sha256=%s\ninstalled config: %s — matches the last recorded install (apply)\n", head1.Hash, plainHash) +
		"anchors: none (if this root is meant to be anchored — integrity.yaml anchor: tlog — run: agenthof audit anchor)\n"
	if code, got := verifyControl(t, "--control-log", plain, "--offline"); code != 0 || got != want {
		t.Fatalf("no anchors: exit %d\n--- got ---\n%s--- want ---\n%s", code, got, want)
	}
}

// TestVerifyControlPlantedHashNeverReachesTheTerminalRaw: a hand-written
// ledger can carry any bytes as the recorded hash. The gate's line strips
// control characters from it, the verdict is the structural hex refusal
// (exit 6), and no byte of the planted value that could drive a terminal
// is printed.
func TestVerifyControlPlantedHashNeverReachesTheTerminalRaw(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	ctl, _ := anchoredViaStub(t)
	rewriteTail(t, ctl, 2, func(seq int, m map[string]any) {
		m["anchor"].(map[string]any)["hash"] = "\x07nope\x1b[31m"
	})
	code, out := verifyControl(t, "--control-log", ctl, "--offline")
	if code != exitAnchorMismatch {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if strings.ContainsAny(out, "\x07\x1b") {
		t.Fatalf("a control character reached the output:\n%q", out)
	}
	if !strings.Contains(out, "anchor seq 1 nope[31m → http://stub.invalid entry ") || !strings.Contains(out, ": MISMATCH — anchor hash is not a lowercase hex sha256\n") {
		t.Fatalf("output:\n%s", out)
	}
}
