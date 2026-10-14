// Package anchorverify decides every successful anchor record a control
// ledger carries: the structural check first (control.CheckAnchors — does
// the chain still reproduce the recorded head?), then the stored proof under
// a backend built from the record's own backend_kind and backend, under a
// key the caller resolves. It is the one place the mismatch / unverifiable
// split lives; audit verify control and investigate both call it, so the two
// views can never name one anchor differently. It reads nothing but the
// records it is handed — no posture, no key file: the pin arrives through
// Options.ResolveKey — and makes no network call unless a backend does (an
// offline backend never does).
package anchorverify

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"time"

	"github.com/agenthof/agenthof/internal/anchor"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/ledger"
)

// State is one verdict on one successful anchor record. The three words are
// the ones audit verify control prints and investigate/1 carries; they never
// change meaning.
type State string

const (
	StateVerified     State = "verified"     // the chain reproduces the head, and the stored proof verifies under the trusted key
	StateMismatch     State = "mismatch"     // a definitive content disagreement — exit 6 at the gate
	StateUnverifiable State = "unverifiable" // no verdict could be reached — exit 7 at the gate; never tamper detected
)

// Result is the verdict on one anchor record, with the structural check it
// came from. Check.Anchor is nil for a success record that carries no
// payload (a StateMismatch, "anchor record without coverage"). Check is a
// named field, not embedded: Check.Mismatch is the structural cause string
// and must not read as the State.
type Result struct {
	Check control.AnchorCheck // RecordSeq, Anchor, Mismatch — as CheckAnchors returned it
	State State
	Cause string // "" when StateVerified; otherwise a fixed phrase plus identifiers, never a response body
}

// Factory builds the Backend a record's own backend_kind and backend name —
// never integrity.yaml — under key (nil = unpinned) and offline. A kind the
// build does not construct is an error, which Verify reports as
// StateUnverifiable.
type Factory func(kind, url string, key *ecdsa.PublicKey, offline bool) (anchor.Backend, error)

// Default is the one kind→backend dispatch for the verify path:
// "transparency-log" builds a Rekor client; anything else is not
// implemented. The CLI's own dispatch returns the same text for an unknown
// kind, pinned equal by a test there.
func Default(kind, url string, key *ecdsa.PublicKey, offline bool) (anchor.Backend, error) {
	switch kind {
	case "transparency-log":
		return anchor.NewRekor(url, anchor.RekorOptions{Key: key, Offline: offline})
	default:
		return nil, fmt.Errorf("anchor backend kind %q is not implemented", kind)
	}
}

// Options parameterizes Verify. ResolveKey is called at most once, and only
// when there is at least one success anchor record to check — exactly when
// audit verify control resolves its pin; nil means unpinned. A resolve error
// does not stop the run: every anchor past the structural check is
// StateUnverifiable with that error as its Cause. Factory nil means Default.
// Offline makes the backend verify from the stored proof only (no served-key
// fetch, no presence check). Timeout bounds each Verify call (0 →
// DefaultTimeout).
type Options struct {
	ResolveKey func() (*ecdsa.PublicKey, error)
	Factory    Factory
	Offline    bool
	Timeout    time.Duration
}

// DefaultTimeout is the per-anchor bound when Options.Timeout is zero.
const DefaultTimeout = 30 * time.Second

// Verify decides every successful anchor record records carry, in chain
// order, and returns one Result per record — never fewer: a verdict is never
// dropped. nil when the chain carries no success anchor record (the caller
// prints its own "none" note).
func Verify(records []ledger.Record, o Options) []Result {
	checks := control.CheckAnchors(records)
	if len(checks) == 0 {
		return nil
	}
	var key *ecdsa.PublicKey
	var keyErr error
	if o.ResolveKey != nil {
		key, keyErr = o.ResolveKey()
	}
	factory := o.Factory
	if factory == nil {
		factory = Default
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	out := make([]Result, 0, len(checks))
	for _, c := range checks {
		state, cause := decide(c, key, keyErr, factory, o.Offline, timeout)
		out = append(out, Result{Check: c, State: state, Cause: cause})
	}
	return out
}

// decide is the ladder for one check, in this order and no other: no
// payload → mismatch; a structural mismatch → mismatch; a key that could not
// be resolved → unverifiable; a backend the build does not construct →
// unverifiable; then the backend's own typed verdict, matched with errors.As
// so a wrapped verdict keeps its class; anything else from the backend is
// the absence of a verdict, never tamper detected. The helper never inspects
// key == nil: whether no key is a verdict is the backend's ruling.
func decide(c control.AnchorCheck, key *ecdsa.PublicKey, keyErr error, factory Factory, offline bool, timeout time.Duration) (State, string) {
	a := c.Anchor
	switch {
	case a == nil, c.Mismatch != "":
		return StateMismatch, c.Mismatch
	case keyErr != nil:
		return StateUnverifiable, keyErr.Error()
	}
	be, err := factory(a.BackendKind, a.Backend, key, offline)
	if err != nil {
		return StateUnverifiable, err.Error()
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	verr := be.Verify(ctx, anchor.Head{Seq: a.Seq, Hash: a.Hash}, anchor.Receipt{Ref: a.Ref, Proof: a.Proof, Backend: a.Backend, BackendKeyID: a.BackendKeyID})
	var m *anchor.Mismatch
	var u *anchor.Unavailable
	switch {
	case verr == nil:
		return StateVerified, ""
	case errors.As(verr, &m):
		return StateMismatch, m.Cause
	case errors.As(verr, &u):
		return StateUnverifiable, u.Cause
	default:
		return StateUnverifiable, verr.Error()
	}
}
