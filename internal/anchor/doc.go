// Package anchor pins a control-ledger head to an external witness — a
// transparency log today, a timestamp authority later — and verifies such a
// pin. A Backend is one witness kind. It is handed a head (seq, hash) and
// returns a Receipt; it never sees the ledger, the posture file, or a
// credential value (a resolver supplies a bearer at call time). The package
// imports nothing else of this module, so any package may consume it.
//
// The crypto is consumed, not rebuilt: RFC 6962 inclusion verification and
// the leaf hash come from github.com/transparency-dev/merkle; signed-note
// (checkpoint) parsing and the unknown-key / bad-signature distinction from
// golang.org/x/mod/sumdb/note. This package adds only the ECDSA P-256 glue
// those two need to meet a Rekor checkpoint, the two REST calls, and the
// verdict classification.
package anchor
