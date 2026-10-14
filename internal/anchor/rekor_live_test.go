//go:build rekor_live

package anchor_test

// The one proof that the real log's checkpoint format, key hash and signature
// encoding match the fake: anchors a random digest into the instance named by
// AGENTHOF_TEST_REKOR_URL (e.g. https://rekor.sigstore.dev) and verifies the
// returned proof offline under the key the log serves. Run by hand:
//
//	AGENTHOF_TEST_REKOR_URL=https://rekor.sigstore.dev go test -tags rekor_live -run TestRekorLive ./internal/anchor/
//
// It creates one public, permanent entry per run. Never part of any gate.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/anchor"
)

func TestRekorLive(t *testing.T) {
	url := os.Getenv("AGENTHOF_TEST_REKOR_URL")
	if url == "" {
		t.Skip("AGENTHOF_TEST_REKOR_URL not set")
	}
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	head := anchor.Head{Seq: 1, Hash: hex.EncodeToString(b[:])}
	rk, err := anchor.NewRekor(url, anchor.RekorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	r, err := rk.Submit(ctx, head)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	t.Logf("entry %s index %d integrated %s key %s", r.Ref, r.LogIndex, r.IntegratedTime.Format(time.RFC3339), r.BackendKeyID)
	if err := rk.Verify(ctx, head, r); err != nil {
		t.Fatalf("verify (as served, online): %v", err)
	}
	// Pin the served key and verify offline: the shape every operator relies on.
	pub, _, err := rk.ServedKey(ctx, r.Ref)
	if err != nil {
		t.Fatal(err)
	}
	off, err := anchor.NewRekor(url, anchor.RekorOptions{Key: pub, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := off.Verify(ctx, head, r); err != nil {
		t.Fatalf("verify (pinned, offline): %v", err)
	}
}
