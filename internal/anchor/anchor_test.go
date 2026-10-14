package anchor_test

import (
	"errors"
	"testing"

	"github.com/agenthof/agenthof/internal/anchor"
)

// TestTypedVerdictsAreDistinct: the two verdicts are distinct pointer types a
// caller tells apart with errors.As, and their texts name the kind — the CLI
// maps them to exit 6 and exit 7 and must never fold one into the other.
func TestTypedVerdictsAreDistinct(t *testing.T) {
	var m *anchor.Mismatch
	var u *anchor.Unavailable
	err := error(&anchor.Mismatch{Cause: "log entry hash differs from the recorded head"})
	if !errors.As(err, &m) || errors.As(err, &u) || err.Error() != "anchor mismatch: log entry hash differs from the recorded head" {
		t.Fatalf("mismatch: %v", err)
	}
	err = &anchor.Unavailable{Cause: "no key to verify under (unpinned, offline)"}
	if !errors.As(err, &u) || errors.As(err, &m) || err.Error() != "anchor unverifiable: no key to verify under (unpinned, offline)" {
		t.Fatalf("unavailable: %v", err)
	}
}

func TestMaxProofLenIs8192(t *testing.T) {
	if anchor.MaxProofLen != 8192 {
		t.Fatalf("MaxProofLen = %d", anchor.MaxProofLen)
	}
}
