package confiner

import (
	"errors"
	"testing"
)

func TestErrArtifactMismatchIsDistinct(t *testing.T) {
	if ErrArtifactMismatch == nil {
		t.Fatal("ErrArtifactMismatch must exist")
	}
	for _, other := range []error{ErrDidNotLaunch, ErrStoreInUse, ErrEmptyProgram, ErrNotImplemented, ErrUnconsumedKeys, ErrNotLocalEngine} {
		if errors.Is(ErrArtifactMismatch, other) || errors.Is(other, ErrArtifactMismatch) {
			t.Fatalf("ErrArtifactMismatch must be distinct from %v", other)
		}
	}
}
