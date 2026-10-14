// Package anchortest holds the test-only anchor backends: Stub, an rfc3161-kind
// Backend that mints an HMAC token and never touches a network, and RekorV1,
// an httptest fake of the Rekor v1 API. Imported only by tests, so neither
// compiles into the binary (the internal/identity/oidctest precedent).
package anchortest

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/agenthof/agenthof/internal/anchor"
)

// StubBackend is Receipt.Backend on every stub receipt. The .invalid TLD never
// resolves, so even a leak into a real dial fails without reaching anything.
const StubBackend = "http://stub.invalid"

// Stub is the rfc3161-kind Backend for tests: a bounded "token" over the head
// — an HMAC-SHA256 under a per-stub secret, with a timestamp — carried in
// Proof, with Ref the sha256 of Proof and no key identity. It is
// deterministic for one secret, so an anchor made by one Stub verifies under
// another built with the same secret (two CLI invocations in one test). It
// holds no http.Client: there is no network to touch.
type Stub struct {
	secret []byte
	now    func() time.Time

	mu   sync.Mutex
	pad  int
	deny bool
	fail bool
}

var _ anchor.Backend = (*Stub)(nil)

// NewStub returns a Stub signing with secret.
func NewStub(secret []byte) *Stub { return &Stub{secret: secret, now: time.Now} }

// Kind is the IntegrityBackend.Kind vocabulary for a timestamp authority.
func (s *Stub) Kind() string { return "rfc3161" }

// Deny makes every later Verify a *anchor.Mismatch, Fail a *anchor.Unavailable
// (Fail wins), and Pad adds n filler bytes to every later token so Submit can
// be driven over MaxProofLen.
func (s *Stub) Deny()     { s.mu.Lock(); s.deny = true; s.mu.Unlock() }
func (s *Stub) Fail()     { s.mu.Lock(); s.fail = true; s.mu.Unlock() }
func (s *Stub) Pad(n int) { s.mu.Lock(); s.pad = n; s.mu.Unlock() }

type stubToken struct {
	Hash string `json:"hash"`
	Time string `json:"time"`
	Pad  string `json:"pad,omitempty"`
	MAC  string `json:"mac"`
}

func (s *Stub) mac(hash, at string) string {
	m := hmac.New(sha256.New, s.secret)
	_, _ = m.Write([]byte(hash + "\n" + at))
	return hex.EncodeToString(m.Sum(nil))
}

// Submit mints the token. It refuses a token over MaxProofLen.
func (s *Stub) Submit(_ context.Context, head anchor.Head) (anchor.Receipt, error) {
	s.mu.Lock()
	pad := s.pad
	s.mu.Unlock()
	at := s.now().UTC().Truncate(time.Second)
	tok := stubToken{Hash: head.Hash, Time: at.Format(time.RFC3339), Pad: strings.Repeat("x", pad)}
	tok.MAC = s.mac(tok.Hash, tok.Time)
	raw, err := json.Marshal(tok)
	if err != nil {
		return anchor.Receipt{}, err
	}
	proof := base64.StdEncoding.EncodeToString(raw)
	if len(proof) > anchor.MaxProofLen {
		return anchor.Receipt{}, fmt.Errorf("stub: proof is %d bytes; the cap is %d", len(proof), anchor.MaxProofLen)
	}
	sum := sha256.Sum256([]byte(proof))
	return anchor.Receipt{Ref: hex.EncodeToString(sum[:]), Proof: proof, Backend: StubBackend, IntegratedTime: at, LogIndex: -1}, nil
}

// Verify is offline: it checks sha256(Proof) == Ref, the HMAC, and that the
// token covers head — each failure a *anchor.Mismatch.
func (s *Stub) Verify(_ context.Context, head anchor.Head, r anchor.Receipt) error {
	s.mu.Lock()
	fail, deny := s.fail, s.deny
	s.mu.Unlock()
	if fail {
		return &anchor.Unavailable{Cause: "stub: unavailable"}
	}
	sum := sha256.Sum256([]byte(r.Proof))
	if hex.EncodeToString(sum[:]) != r.Ref {
		return &anchor.Mismatch{Cause: "proof does not hash to the recorded ref"}
	}
	raw, err := base64.StdEncoding.DecodeString(r.Proof)
	if err != nil {
		return &anchor.Mismatch{Cause: "proof is not base64"}
	}
	var tok stubToken
	if err := json.Unmarshal(raw, &tok); err != nil {
		return &anchor.Mismatch{Cause: "proof does not decode"}
	}
	if !hmac.Equal([]byte(tok.MAC), []byte(s.mac(tok.Hash, tok.Time))) {
		return &anchor.Mismatch{Cause: "token is not signed by this backend"}
	}
	if tok.Hash != head.Hash {
		return &anchor.Mismatch{Cause: "token covers another head"}
	}
	if deny {
		return &anchor.Mismatch{Cause: "stub: denied"}
	}
	return nil
}
