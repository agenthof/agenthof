package anchortest_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/anchor"
	"github.com/agenthof/agenthof/internal/anchor/anchortest"
)

var _ anchor.Backend = (*anchortest.Stub)(nil)

var head = anchor.Head{Seq: 7, Hash: strings.Repeat("ab", 32)}

// TestStubSubmitFillsProofAndRefIsItsDigest: Proof is non-empty standard
// base64 under the cap, Ref is sha256(Proof), there is no key identity, and
// the receipt names the stub backend.
func TestStubSubmitFillsProofAndRefIsItsDigest(t *testing.T) {
	s := anchortest.NewStub([]byte("secret"))
	r, err := s.Submit(context.Background(), head)
	if err != nil {
		t.Fatal(err)
	}
	if r.Proof == "" || len(r.Proof) > anchor.MaxProofLen {
		t.Fatalf("proof = %d bytes", len(r.Proof))
	}
	if _, err := base64.StdEncoding.DecodeString(r.Proof); err != nil {
		t.Fatalf("proof is not standard base64: %v", err)
	}
	sum := sha256.Sum256([]byte(r.Proof))
	if r.Ref != hex.EncodeToString(sum[:]) || r.BackendKeyID != "" || r.Backend != anchortest.StubBackend || r.LogIndex != -1 || r.IntegratedTime.IsZero() {
		t.Fatalf("receipt = %+v", r)
	}
	if s.Kind() != "rfc3161" {
		t.Fatalf("Kind = %q", s.Kind())
	}
}

// TestStubVerifyIsOfflineAndDeterministic: a second Stub with the same secret
// verifies the first's receipt (two CLI processes in one test); a flipped
// proof byte, a proof for another head and a wrong ref are each *Mismatch;
// Deny forces *Mismatch and Fail forces *Unavailable.
func TestStubVerifyIsOfflineAndDeterministic(t *testing.T) {
	a, b := anchortest.NewStub([]byte("secret")), anchortest.NewStub([]byte("secret"))
	r, err := a.Submit(context.Background(), head)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Verify(context.Background(), head, r); err != nil {
		t.Fatalf("same secret must verify: %v", err)
	}
	var m *anchor.Mismatch
	var u *anchor.Unavailable
	flipped := r
	flipped.Proof = "A" + r.Proof[1:]
	if err := b.Verify(context.Background(), head, flipped); !errors.As(err, &m) {
		t.Fatalf("flipped proof: %v", err)
	}
	if err := b.Verify(context.Background(), anchor.Head{Seq: 8, Hash: strings.Repeat("cd", 32)}, r); !errors.As(err, &m) {
		t.Fatalf("another head: %v", err)
	}
	other := anchortest.NewStub([]byte("another secret"))
	if err := other.Verify(context.Background(), head, r); !errors.As(err, &m) {
		t.Fatalf("another secret: %v", err)
	}
	b.Deny()
	if err := b.Verify(context.Background(), head, r); !errors.As(err, &m) {
		t.Fatalf("Deny: %v", err)
	}
	c := anchortest.NewStub([]byte("secret"))
	c.Fail()
	if err := c.Verify(context.Background(), head, r); !errors.As(err, &u) {
		t.Fatalf("Fail: %v", err)
	}
}

// TestStubRefusesAProofOverTheCap: Pad makes the token exceed MaxProofLen and
// Submit refuses — the cap is enforced by the backend before the record.
func TestStubRefusesAProofOverTheCap(t *testing.T) {
	s := anchortest.NewStub([]byte("secret"))
	s.Pad(anchor.MaxProofLen)
	if _, err := s.Submit(context.Background(), head); err == nil || !strings.Contains(err.Error(), "the cap is 8192") {
		t.Fatalf("err = %v", err)
	}
}
