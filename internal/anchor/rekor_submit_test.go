package anchor_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/anchor"
	"github.com/agenthof/agenthof/internal/anchor/anchortest"
	"github.com/transparency-dev/merkle/rfc6962"
)

var head41 = anchor.Head{Seq: 41, Hash: strings.Repeat("ab", 32)}

type envelope struct {
	V          string   `json:"v"`
	Body       string   `json:"body"`
	LogIndex   int64    `json:"log_index"`
	TreeSize   int64    `json:"tree_size"`
	RootHash   string   `json:"root_hash"`
	Hashes     []string `json:"hashes"`
	Checkpoint string   `json:"checkpoint"`
}

func decodeEnvelope(t *testing.T, proof string) envelope {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(proof)
	if err != nil {
		t.Fatal(err)
	}
	var e envelope
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	return e
}

func newRekor(t *testing.T, f *anchortest.RekorV1, o anchor.RekorOptions) *anchor.Rekor {
	t.Helper()
	rk, err := anchor.NewRekor(f.URL, o)
	if err != nil {
		t.Fatal(err)
	}
	return rk
}

// recorder is an http.RoundTripper that wraps the default transport, keeps a
// copy of the headers of the last request sent, and can answer the next
// request with a huge 201 body so the 1 MiB cap is exercised without a real
// 1 MiB tree.
type recorder struct {
	mu   sync.Mutex
	last http.Header
	huge int
}

func (rc *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	rc.mu.Lock()
	rc.last = req.Header.Clone()
	huge := rc.huge
	rc.huge = 0
	rc.mu.Unlock()
	if huge > 0 {
		return &http.Response{
			StatusCode: http.StatusCreated,
			Status:     "201 Created",
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("x"), huge))),
			Request:    req,
		}, nil
	}
	return http.DefaultTransport.RoundTrip(req)
}

func (rc *recorder) LastHeaders() http.Header {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.last.Clone()
}

func (rc *recorder) HugeNext(n int) {
	rc.mu.Lock()
	rc.huge = n
	rc.mu.Unlock()
}

// TestRekorSubmitHappyPath: Ref is treeID ‖ HashLeaf(body) in 80
// lowercase hex; Proof decodes as a rekor-v1-proof/1 envelope whose body,
// hashes and checkpoint are what the fake served; BackendKeyID is the fake's
// key id; IntegratedTime/LogIndex as served; Backend is the URL as given; the
// POST was a valid hashedrekord 0.0.1 whose data.hash.value is the head and
// whose signature verifies under the embedded key with ecdsa.VerifyASN1 — a
// key that is NOT any key on disk.
func TestRekorSubmitHappyPath(t *testing.T) {
	f := anchortest.NewRekorV1()
	t.Cleanup(f.Close)
	onDisk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) // stands for signing.key beside a ledger
	rk := newRekor(t, f, anchor.RekorOptions{})
	r, err := rk.Submit(context.Background(), head41)
	if err != nil {
		t.Fatal(err)
	}
	env := decodeEnvelope(t, r.Proof)
	body, _ := base64.StdEncoding.DecodeString(env.Body)
	wantRef := fmt.Sprintf("%016x", f.TreeID()) + hex.EncodeToString(rfc6962.DefaultHasher.HashLeaf(body))
	if r.Ref != wantRef || len(r.Ref) != 80 || r.Ref != strings.ToLower(r.Ref) {
		t.Fatalf("Ref = %q, want %q", r.Ref, wantRef)
	}
	if env.V != "rekor-v1-proof/1" || env.Checkpoint == "" || len(env.Hashes) != 0 || env.TreeSize != 1 || env.LogIndex != 0 { // first leaf: no siblings
		t.Fatalf("envelope %+v", env)
	}
	wantID, _ := anchor.KeyID(f.PublicKey())
	if r.BackendKeyID != wantID || r.Backend != f.URL || r.LogIndex != 0 || time.Since(r.IntegratedTime) > time.Minute || r.IntegratedTime.Location() != time.UTC {
		t.Fatalf("receipt %+v", r)
	}
	if len(r.Proof) > anchor.MaxProofLen {
		t.Fatalf("proof %d bytes", len(r.Proof))
	}

	var posted struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Spec       struct {
			Data struct {
				Hash struct{ Algorithm, Value string } `json:"hash"`
			} `json:"data"`
			Signature struct {
				Content   string                   `json:"content"`
				PublicKey struct{ Content string } `json:"publicKey"`
			} `json:"signature"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(f.LastProposed(), &posted); err != nil {
		t.Fatal(err)
	}
	if posted.Kind != "hashedrekord" || posted.APIVersion != "0.0.1" || posted.Spec.Data.Hash.Algorithm != "sha256" || posted.Spec.Data.Hash.Value != head41.Hash {
		t.Fatalf("posted %+v", posted)
	}
	pemBytes, _ := base64.StdEncoding.DecodeString(posted.Spec.Signature.PublicKey.Content)
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Fatal("public key must be PEM PKIX")
	}
	pub, err := anchor.ParseLogKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := base64.StdEncoding.DecodeString(posted.Spec.Signature.Content)
	digest, _ := hex.DecodeString(head41.Hash)
	if !ecdsa.VerifyASN1(pub, digest, sig) {
		t.Fatal("the entry's signature must verify under the embedded key")
	}
	if pub.Equal(&onDisk.PublicKey) {
		t.Fatal("the ephemeral key must not be a key on disk")
	}
	r2, err := rk.Submit(context.Background(), head41) // same head twice: two entries, never a 409
	if err != nil || r2.Ref == r.Ref {
		t.Fatalf("second submit: %v %q", err, r2.Ref)
	}
}

// TestRekorSubmitVerifiesBeforeReturning: a 201 whose body does
// not hash to its entry id is an error and no Receipt; with a pinned key and
// the log signing under another key, an error naming the pinned-key fix.
func TestRekorSubmitVerifiesBeforeReturning(t *testing.T) {
	f := anchortest.NewRekorV1()
	t.Cleanup(f.Close)
	f.CorruptNext()
	if r, err := newRekor(t, f, anchor.RekorOptions{}).Submit(context.Background(), head41); err == nil || r.Ref != "" {
		t.Fatalf("corrupt create: %v %+v", err, r)
	}
	pinned := f.PublicKey()
	f.RotateKey()
	_, err := newRekor(t, f, anchor.RekorOptions{Key: pinned}).Submit(context.Background(), head41)
	if err == nil || !strings.Contains(err.Error(), "log key differs from the pinned key") {
		t.Fatalf("rotated under a pin: %v", err)
	}
	if f.Entries() != 2 {
		t.Fatalf("both entries were created at the log (%d); the failure is the client's refusal to vouch", f.Entries())
	}
}

// TestRekorSubmitFailuresClassifiedIdentically: every non-201 is
// "status N from <host>" with nothing from the response; a dropped connection
// and a timeout are errors; a proof over MaxProofLen is refused.
func TestRekorSubmitFailuresClassifiedIdentically(t *testing.T) {
	f := anchortest.NewRekorV1()
	t.Cleanup(f.Close)
	rk := newRekor(t, f, anchor.RekorOptions{})
	host := strings.TrimPrefix(f.URL, "http://")
	for _, status := range []int{501, 405, 409, 500, 302, 400} {
		f.Fail(status)
		_, err := rk.Submit(context.Background(), head41)
		if err == nil || err.Error() != "status "+strconv.Itoa(status)+" from "+host {
			t.Fatalf("status %d: err = %v", status, err)
		}
		if strings.Contains(err.Error(), anchortest.Sentinel) {
			t.Fatalf("response text leaked: %v", err)
		}
	}
	f.Drop()
	if _, err := rk.Submit(context.Background(), head41); err == nil || !strings.HasPrefix(err.Error(), host+": ") {
		t.Fatalf("drop: %v", err)
	}
	f.Start()
	f.Delay(time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := rk.Submit(ctx, head41); err == nil {
		t.Fatal("timeout must error")
	}
	f.Reset()
	f.PadProof(130) // 130 × 64 hex ≈ 8.3 KB of hashes alone
	if _, err := rk.Submit(context.Background(), head41); err == nil || !strings.Contains(err.Error(), "the cap is 8192") {
		t.Fatalf("over cap: %v", err)
	}
	if _, err := rk.Submit(context.Background(), anchor.Head{Seq: 1, Hash: "ABCD"}); err == nil || !strings.Contains(err.Error(), "is not a lowercase hex sha256") {
		t.Fatalf("bad head hash: %v", err)
	}
}

// TestRekorHTTPHygiene: NewRekor refuses a URL that is not an
// absolute http(s) URL without credentials, query or fragment; trims one
// trailing slash; never follows a redirect (a 302 is "status 302"); sends
// Accept: application/json and Authorization only when a bearer is given;
// refuses a body over 1 MiB.
func TestRekorHTTPHygiene(t *testing.T) {
	for _, bad := range []string{"", "rekor.sigstore.dev", "ftp://rekor.sigstore.dev", "https://user:pw@rekor.sigstore.dev", "https://rekor.sigstore.dev/?x=1", "https://rekor.sigstore.dev/#frag", "https://"} {
		if _, err := anchor.NewRekor(bad, anchor.RekorOptions{}); err == nil || !strings.Contains(err.Error(), "is not an absolute http(s) URL without credentials") {
			t.Fatalf("%q: err = %v", bad, err)
		}
	}
	f := anchortest.NewRekorV1()
	t.Cleanup(f.Close)
	rec := &recorder{}
	client := &http.Client{Transport: rec}
	rk := newRekor(t, f, anchor.RekorOptions{Client: client, Bearer: func(context.Context) (string, error) { return "tok-123", nil }})
	rk2, err := anchor.NewRekor(f.URL+"/", anchor.RekorOptions{Client: client})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := rk2.Submit(context.Background(), head41)
	if err != nil || r2.Backend != f.URL {
		t.Fatalf("trailing slash must be trimmed: %v %q", err, r2.Backend)
	}
	hdr := rec.LastHeaders()
	if hdr.Get("Accept") != "application/json" || hdr.Get("Authorization") != "" {
		t.Fatalf("anonymous request headers %v", hdr)
	}
	r, err := rk.Submit(context.Background(), head41)
	if err != nil || r.Backend != f.URL {
		t.Fatalf("%v %q", err, r.Backend)
	}
	if rec.LastHeaders().Get("Authorization") != "Bearer tok-123" {
		t.Fatalf("bearer not injected: %v", rec.LastHeaders())
	}
	f.Fail(302)
	if _, err := rk.Submit(context.Background(), head41); err == nil || !strings.HasPrefix(err.Error(), "status 302 from ") {
		t.Fatalf("redirect must not be followed: %v", err)
	}
	if reqs := f.Requests(); len(reqs) == 0 || reqs[len(reqs)-1] != "POST /api/v1/log/entries" {
		t.Fatalf("the 302 must be the last request the log saw (no redirect followed): %v", reqs)
	}
	rec.HugeNext(2 << 20)
	if _, err := rk.Submit(context.Background(), head41); err == nil || !strings.Contains(err.Error(), "exceeds 1 MiB") {
		t.Fatalf("oversized body: %v", err)
	}
}

// TestRekorSubmitDoesNotLeakServerControlledEntryID: a 201 whose single entry
// key is not 80 hex must not place that key into the error — the error is
// recorded verbatim in the control ledger (spec §8 step 7: fixed phrases +
// status + URL host, never response content).
func TestRekorSubmitDoesNotLeakServerControlledEntryID(t *testing.T) {
	body := []byte(`{"` + anchortest.Sentinel + `":{"body":"","integratedTime":0,"logIndex":0,"logID":"x","verification":{"inclusionProof":{"logIndex":0,"treeSize":1,"rootHash":"","hashes":[],"checkpoint":{"envelope":""}}}}}`)
	rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusCreated,
			Status:     "201 Created",
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(body)),
			Request:    req,
		}, nil
	})
	rk, err := anchor.NewRekor("http://log.example", anchor.RekorOptions{Client: &http.Client{Transport: rt}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = rk.Submit(context.Background(), head41)
	if err == nil {
		t.Fatal("want an error on an id that is not 80 hex")
	}
	if strings.Contains(err.Error(), anchortest.Sentinel) {
		t.Fatalf("server-controlled id leaked into recorded error: %v", err)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
