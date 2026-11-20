package confinertest

import (
	"context"
	"slices"
	"testing"

	"github.com/agenthof/agenthof/deploy/internal/confiner"
)

func TestFakeRecordsExpectedAndReportsSettableRan(t *testing.T) {
	ctx := context.Background()
	f := New(t.TempDir())
	if exp, ok := f.LastExpected(); ok || exp != nil {
		t.Fatalf("no launch yet: got %v, %v", exp, ok)
	}
	f.Ran = &confiner.ExpectedArtifact{Kind: "image", Values: []string{"sha256:aa"}}
	want := &confiner.ExpectedArtifact{Kind: "image", Values: []string{"sha256:aa", "sha256:bb"}}
	c, err := f.Launch(ctx, confiner.Spec{Name: "n1", Argv: []string{"true"}, Expected: want})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	got, ok := f.LastExpected()
	if !ok || got == nil || got.Kind != "image" || !slices.Equal(got.Values, want.Values) {
		t.Fatalf("recorded Expected = %v, %v", got, ok)
	}
	kind, values, ok := c.RanArtifact()
	if !ok || kind != "image" || !slices.Equal(values, []string{"sha256:aa"}) {
		t.Fatalf("RanArtifact = %q %v %v", kind, values, ok)
	}

	// An unset Ran reports not-measured, and a nil Expected is recorded as nil.
	g := New(t.TempDir())
	c2, err := g.Launch(ctx, confiner.Spec{Name: "n2", Argv: []string{"true"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c2.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := c2.RanArtifact(); ok {
		t.Fatal("unset Ran must report ok=false")
	}
	if exp, ok := g.LastExpected(); !ok || exp != nil {
		t.Fatalf("nil Expected must be recorded as nil: %v, %v", exp, ok)
	}
}
