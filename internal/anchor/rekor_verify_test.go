package anchor_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/anchor"
	"github.com/agenthof/agenthof/internal/anchor/anchortest"
)

// Rekor implements the whole Backend interface.
var _ anchor.Backend = (*anchor.Rekor)(nil)

// anchored submits head41 and returns the fake, the receipt, and a Rekor under
// o for verifying it.
func anchored(t *testing.T, o anchor.RekorOptions) (*anchortest.RekorV1, anchor.Receipt, *anchor.Rekor) {
	t.Helper()
	f := anchortest.NewRekorV1()
	t.Cleanup(f.Close)
	r, err := newRekor(t, f, anchor.RekorOptions{}).Submit(context.Background(), head41)
	if err != nil {
		t.Fatal(err)
	}
	return f, r, newRekor(t, f, o)
}

func reencode(t *testing.T, env envelope) string {
	t.Helper()
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func wantMismatch(t *testing.T, err error, cause string) {
	t.Helper()
	var m *anchor.Mismatch
	if !errors.As(err, &m) || !strings.Contains(m.Cause, cause) {
		t.Fatalf("err = %v, want *Mismatch containing %q", err, cause)
	}
}

func wantUnavailable(t *testing.T, err error, cause string) {
	t.Helper()
	var u *anchor.Unavailable
	if !errors.As(err, &u) || !strings.Contains(u.Cause, cause) {
		t.Fatalf("err = %v, want *Unavailable containing %q", err, cause)
	}
}

// TestRekorVerifyPassesAndInformational: happy path pinned → nil;
// unpinned online → nil; a renamed origin → nil (hostname is informational);
// a cosigned checkpoint → nil; Offline under the pinned key with the fake
// STOPPED → nil (the stored proof decides).
func TestRekorVerifyPassesAndInformational(t *testing.T) {
	f, r, rk := anchored(t, anchor.RekorOptions{})
	pinned := newRekor(t, f, anchor.RekorOptions{Key: f.PublicKey()})
	if err := pinned.Verify(context.Background(), head41, r); err != nil {
		t.Fatalf("pinned: %v", err)
	}
	if err := rk.Verify(context.Background(), head41, r); err != nil {
		t.Fatalf("unpinned online: %v", err)
	}
	f2 := anchortest.NewRekorV1()
	t.Cleanup(f2.Close)
	f2.SetHostname("elsewhere")
	f2.Cosign()
	r2, err := newRekor(t, f2, anchor.RekorOptions{}).Submit(context.Background(), head41)
	if err != nil {
		t.Fatal(err)
	}
	if err := newRekor(t, f2, anchor.RekorOptions{Key: f2.PublicKey()}).Verify(context.Background(), head41, r2); err != nil {
		t.Fatalf("renamed + cosigned: %v", err)
	}
	f.Stop()
	before := len(f.Requests())
	off := newRekor(t, f, anchor.RekorOptions{Key: f.PublicKey(), Offline: true})
	if err := off.Verify(context.Background(), head41, r); err != nil {
		t.Fatalf("offline under the pinned key with the log stopped: %v", err)
	}
	if n := len(f.Requests()); n != before { // nothing from the offline verify
		t.Fatalf("offline verify made a request: %v", f.Requests()[before:])
	}
}

// TestRekorVerifyKeyIdentityIsUnavailable: a
// pinned key other than the signer; unpinned after RotateKey (served id ≠
// recorded); unpinned with the publicKey endpoint failing; unpinned Offline.
func TestRekorVerifyKeyIdentityIsUnavailable(t *testing.T) {
	f, r, rk := anchored(t, anchor.RekorOptions{})
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wantUnavailable(t, newRekor(t, f, anchor.RekorOptions{Key: &other.PublicKey}).Verify(context.Background(), head41, r), "log key differs from the pinned key")
	f.RotateKey()
	wantUnavailable(t, rk.Verify(context.Background(), head41, r), "recorded at anchor time")
	f.Fail(500)
	wantUnavailable(t, rk.Verify(context.Background(), head41, r), "status 500 from")
	wantUnavailable(t, newRekor(t, f, anchor.RekorOptions{Offline: true}).Verify(context.Background(), head41, r), "no key to verify under")
}

// TestRekorVerifyContentIsMismatch: every content disagreement
// under the correct pinned key is *Mismatch.
func TestRekorVerifyContentIsMismatch(t *testing.T) {
	f, r, _ := anchored(t, anchor.RekorOptions{})
	rk := newRekor(t, f, anchor.RekorOptions{Key: f.PublicKey(), Offline: true})
	env := decodeEnvelope(t, r.Proof)
	ctx := context.Background()

	// A second leaf so the proof has a sibling hash to tamper with.
	if _, err := newRekor(t, f, anchor.RekorOptions{}).Submit(ctx, anchor.Head{Seq: 42, Hash: strings.Repeat("cd", 32)}); err != nil {
		t.Fatal(err)
	}
	r2, err := newRekor(t, f, anchor.RekorOptions{}).Submit(ctx, anchor.Head{Seq: 43, Hash: strings.Repeat("ef", 32)})
	if err != nil {
		t.Fatal(err)
	}
	env2 := decodeEnvelope(t, r2.Proof)
	head43 := anchor.Head{Seq: 43, Hash: strings.Repeat("ef", 32)}

	wantMismatch(t, rk.Verify(ctx, anchor.Head{Seq: 41, Hash: strings.Repeat("00", 32)}, r), "log entry hash differs from the recorded head")
	badRef := r
	badRef.Ref = r.Ref[:16] + strings.Repeat("0", 64)
	wantMismatch(t, rk.Verify(ctx, head41, badRef), "leaf hash differs from the recorded ref")
	tampered := env2
	tampered.Hashes = append([]string(nil), env2.Hashes...)
	tampered.Hashes[0] = strings.Repeat("11", 32)
	wantMismatch(t, rk.Verify(ctx, head43, anchor.Receipt{Ref: r2.Ref, Proof: reencode(t, tampered)}), "inclusion proof does not verify")
	badRoot := env2
	badRoot.RootHash = strings.Repeat("22", 32)
	wantMismatch(t, rk.Verify(ctx, head43, anchor.Receipt{Ref: r2.Ref, Proof: reencode(t, badRoot)}), "proof root differs from the checkpoint")
	flipped := env
	cp, err := anchortest.FlipSignature([]byte(env.Checkpoint)) // one byte inside the signature; the key hash stays
	if err != nil {
		t.Fatal(err)
	}
	flipped.Checkpoint = string(cp)
	wantMismatch(t, rk.Verify(ctx, head41, anchor.Receipt{Ref: r.Ref, Proof: reencode(t, flipped)}), "checkpoint signature under the trusted key is invalid")
	// A checkpoint for another tree id, honestly signed by the log's key. The
	// tree id's last digit changes so it stays a valid uint64.
	otherTree := env
	text := strings.SplitAfter(env.Checkpoint, "\n\n")[0]
	oldOrigin := " - " + strconv.FormatUint(f.TreeID(), 10) + "\n"
	newOrigin := " - " + strconv.FormatUint(f.TreeID()-1, 10) + "\n"
	if !strings.Contains(text, oldOrigin) {
		t.Fatalf("checkpoint origin not found in %q", text)
	}
	text = strings.Replace(text, oldOrigin, newOrigin, 1)
	line, err := anchortest.SignNote(f.PrivateKey(), "rekor.test", strings.TrimSuffix(text, "\n"))
	if err != nil {
		t.Fatal(err)
	}
	otherTree.Checkpoint = text + string(line)
	wantMismatch(t, rk.Verify(ctx, head41, anchor.Receipt{Ref: r.Ref, Proof: reencode(t, otherTree)}), "checkpoint names tree")

	online := newRekor(t, f, anchor.RekorOptions{Key: f.PublicKey()})
	f.Forget(r.Ref)
	wantMismatch(t, online.Verify(ctx, head41, r), "absent from the log (404)")
	f.Reset()
	f.Corrupt(r.Ref)
	wantMismatch(t, online.Verify(ctx, head41, r), "log serves a different body")
}

// TestRekorVerifyPresenceFailuresAreUnavailable:
// with the proof verified offline under the pinned key, a dropped connection,
// a timeout, a 500, a 302 and a non-JSON 200 on the presence check are each
// *Unavailable whose cause says the proof verified offline.
func TestRekorVerifyPresenceFailuresAreUnavailable(t *testing.T) {
	f, r, _ := anchored(t, anchor.RekorOptions{})
	rk := newRekor(t, f, anchor.RekorOptions{Key: f.PublicKey()})
	f.Drop()
	wantUnavailable(t, rk.Verify(context.Background(), head41, r), "proof verified offline")
	f.Start()
	f.Delay(time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	wantUnavailable(t, rk.Verify(ctx, head41, r), "proof verified offline")
	cancel()
	f.Reset()
	for _, status := range []int{500, 302, 401, 501} {
		f.Fail(status)
		err := rk.Verify(context.Background(), head41, r)
		wantUnavailable(t, err, "status "+strconv.Itoa(status)+" from")
		wantUnavailable(t, err, "proof verified offline")
		if strings.Contains(err.Error(), anchortest.Sentinel) {
			t.Fatalf("response text leaked: %v", err)
		}
	}
	f.GarbageNext()
	err := rk.Verify(context.Background(), head41, r)
	wantUnavailable(t, err, "proof verified offline")
	if strings.Contains(err.Error(), anchortest.Sentinel) {
		t.Fatalf("response text leaked: %v", err)
	}
	if err := rk.Verify(context.Background(), head41, r); err != nil { // the garbage was one-shot
		t.Fatalf("after the garbage: %v", err)
	}
}

// TestRekorVerifyRejectsHostileRecordFields: fields a hostile
// ledger could plant never panic and never reach a host the record did not
// name — a ref that is not 80 hex, a proof that is not base64 or not JSON, an
// envelope version this build does not read, a backend URL that is not an
// absolute http(s) URL.
func TestRekorVerifyRejectsHostileRecordFields(t *testing.T) {
	f, r, _ := anchored(t, anchor.RekorOptions{})
	rk := newRekor(t, f, anchor.RekorOptions{Key: f.PublicKey()})
	unpinned := newRekor(t, f, anchor.RekorOptions{})
	ctx := context.Background()
	for _, ref := range []string{"", "zz", r.Ref[:79], r.Ref + "0", "../../" + r.Ref[:70], strings.Repeat("g", 80), r.Ref[:16] + "\n" + r.Ref[17:]} {
		bad := r
		bad.Ref = ref
		wantMismatch(t, rk.Verify(ctx, head41, bad), "is not an 80-hex entry id")
		wantMismatch(t, unpinned.Verify(ctx, head41, bad), "is not an 80-hex entry id")
	}
	bad := r
	bad.Proof = "!!!"
	wantMismatch(t, rk.Verify(ctx, head41, bad), "proof does not decode")
	bad = r
	bad.Proof = base64.StdEncoding.EncodeToString([]byte(`["not","an","object"]`))
	wantMismatch(t, rk.Verify(ctx, head41, bad), "proof does not decode")
	future := decodeEnvelope(t, r.Proof)
	future.V = "rekor-v2-proof/1"
	wantUnavailable(t, rk.Verify(ctx, head41, anchor.Receipt{Ref: r.Ref, Proof: reencode(t, future)}), "a proof format this build does not read")
	if _, err := anchor.NewRekor("file:///etc/passwd", anchor.RekorOptions{}); err == nil {
		t.Fatal("a non-http backend must be refused at construction")
	}
	if n := len(f.Requests()); n != 2 {
		t.Fatalf("hostile fields must cause no request: %v", f.Requests())
	}
}

// TestRekorServedKey: the exported helper returns the key the log serves for
// a ref's tree and refuses a ref that is not an 80-hex entry id.
func TestRekorServedKey(t *testing.T) {
	f, r, rk := anchored(t, anchor.RekorOptions{})
	pub, id, err := rk.ServedKey(context.Background(), r.Ref)
	if err != nil || !pub.Equal(f.PublicKey()) || id != r.BackendKeyID {
		t.Fatalf("ServedKey = %v, %q, %v", pub, id, err)
	}
	n := len(f.Requests())
	if _, _, err := rk.ServedKey(context.Background(), "zz"); err == nil {
		t.Fatal("a hostile ref must be refused")
	}
	if len(f.Requests()) != n {
		t.Fatal("a hostile ref must cause no request")
	}
}

// TestBackendAsymmetry: one caller, two implementers — a Ref
// that is a live locator with a key identity, and a Ref that is a digest with
// none — both carrying Proof, both verified by the same code.
func TestBackendAsymmetry(t *testing.T) {
	_, r, rk := anchored(t, anchor.RekorOptions{})
	stub := anchortest.NewStub([]byte("s"))
	sr, err := stub.Submit(context.Background(), head41)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		be  anchor.Backend
		rc  anchor.Receipt
		key bool
	}{"rekor": {rk, r, true}, "stub": {stub, sr, false}} {
		if c.rc.Proof == "" || (c.rc.BackendKeyID != "") != c.key {
			t.Fatalf("%s: receipt %+v", name, c.rc)
		}
		if err := c.be.Verify(context.Background(), head41, c.rc); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
