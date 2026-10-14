package anchor

import (
	"context"
	"time"
)

// Head is what gets anchored: one ledger head — the seq of the covered
// record and the hash the ledger prints for it, lowercase hex SHA-256 of that
// record's exact bytes. The hash IS the anchored object: a transparency log
// signs the digest, a timestamp token covers the digest; no backend needs the
// bytes, so none is handed them.
type Head struct {
	Seq  int
	Hash string
}

// Receipt is what a successful Submit returns and what the record keeps:
// everything a later Verify needs, nothing secret. Proof is the witness's own
// evidence, standard base64, bounded by MaxProofLen — a log's inclusion proof
// and signed checkpoint, a TSA's token — so every anchor verifies OFFLINE
// under a key the verifier trusts, for as long as the record exists. Ref is a
// backend-kind-defined locator the verifier may use for a non-load-bearing
// "still present" check.
type Receipt struct {
	Ref            string    // Rekor v1: the 80-hex entry id; stub: sha256 of Proof
	Proof          string    // standard base64, non-empty, ≤ MaxProofLen
	Backend        string    // the service's public identity as configured (absolute URL, one trailing slash trimmed)
	BackendKeyID   string    // identity of the key that signed for the entry: lowercase hex sha256 of its PKIX DER (Rekor's logID); "" for a kind without one
	IntegratedTime time.Time // the witness's own claim of when it took the entry (UTC); informational, never a verdict; zero if none
	LogIndex       int64     // informational, as reported by the log (Rekor: the virtual log index); -1 if none
}

// MaxProofLen bounds Receipt.Proof on the record: 8192 bytes of base64. A
// Rekor v1 proof envelope at a few billion entries is ≈6 KB base64 (measured;
// the cap holds past 2^47 entries); an RFC-3161 token is 1–4 KB DER (≈5.5 KB
// base64); a tile-backed log entry with its checkpoint ≈1.5 KB. Submit refuses
// a larger proof; the control ledger's
// Append refuses a larger record (internal/control.MaxAnchorProofLen is
// documented equal to this constant and a test in cmd/agenthof pins it).
const MaxProofLen = 8192

// Backend is one witness kind. Both methods take a context the caller bounds
// with a timeout; neither may block past it. Verify's error is typed: nil
// means verified; *Mismatch is a CONTENT disagreement under a key that did
// verify (or a structural one) — the witness definitively does not stand
// behind this head as recorded; *Unavailable means no verdict could be
// reached — the witness unreachable, or no key the verifier trusts could be
// matched to the proof (a key-identity disagreement is Unavailable, never
// Mismatch: it says "decide which key to trust", not "tampered"). The CLI maps
// them to exit 6 and exit 7 and must never fold one into the other.
type Backend interface {
	Kind() string // the IntegrityBackend.Kind vocabulary: "transparency-log" | "rfc3161"
	Submit(ctx context.Context, head Head) (Receipt, error)
	Verify(ctx context.Context, head Head, r Receipt) error
}

// Mismatch is a definitive verdict: under a key that verified, the proof
// does not stand behind this head as the record describes. Cause is a fixed
// phrase plus identifiers (never response bodies).
type Mismatch struct{ Cause string }

func (m *Mismatch) Error() string { return "anchor mismatch: " + m.Cause }

// Unavailable is the absence of a verdict: the witness could not be reached,
// or the proof is signed by a key the verifier does not hold — update the
// pinned key, or pin one, to decide. Never a tamper signal.
type Unavailable struct{ Cause string }

func (u *Unavailable) Error() string { return "anchor unverifiable: " + u.Cause }
