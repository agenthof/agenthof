package confiner

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	testImgID     = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testDigest    = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testDigestAlt = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testDigestBad = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

// setTestImage makes the fake podman know exactly one local image, ref, whose
// manifest digest is testDigest and whose repo digests are repoDigests.
func setTestImage(t *testing.T, ref, repoDigests string) {
	t.Helper()
	t.Setenv("CONFINER_TEST_IMAGE", ref+"|"+testImgID+"|"+testDigest+"|"+repoDigests)
}

// runLines are the `podman run` invocations the fake saw.
func runLines(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	for _, l := range readLog(t, root) {
		if strings.HasPrefix(l, "run ") {
			out = append(out, l)
		}
	}
	return out
}

func ociExpected(vals ...string) *ExpectedArtifact {
	return &ExpectedArtifact{Kind: "oci-image", Values: vals}
}

func TestPodmanExpectedDigestMatchRunsByImageIDAndMeasuresTheSet(t *testing.T) {
	p, root := newTestPodman(t)
	// The image is known under a different repo name than the operator's ref,
	// and carries an extra digest the consent did not name.
	setTestImage(t, "example.test/exec:1", "other.test/renamed@"+testDigest+",other.test/renamed@"+testDigestAlt)
	c, err := p.Launch(context.Background(), Spec{Name: "e1", Program: "example.test/exec:1", Store: "work", Timeout: time.Minute,
		Expected: ociExpected(testDigest), Argv: []string{"sh", "-c", "exit 0"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	runs := runLines(t, root)
	if len(runs) != 1 || !strings.Contains(runs[0], " "+testImgID+" ") || strings.Contains(runs[0], "example.test/exec:1") {
		t.Fatalf("must run by the image ID, not the mapped ref: %q", runs)
	}
	kind, vals, ok := c.RanArtifact()
	// Measured, not echoed: Expected named one digest; the image has two.
	if !ok || kind != "oci-image" || !slices.Equal(vals, []string{testDigest, testDigestAlt}) {
		t.Fatalf("RanArtifact = %q %v %v", kind, vals, ok)
	}
}

func TestPodmanExpectedDigestMismatchRefusesSynchronouslyServingNothing(t *testing.T) {
	p, root := newTestPodman(t)
	setTestImage(t, "example.test/exec:1", "example.test/exec@"+testDigest)
	c, err := p.Launch(context.Background(), Spec{Name: "e2", Program: "example.test/exec:1", Store: "work", Timeout: time.Minute,
		Expected: ociExpected(testDigestBad), Argv: []string{"sh", "-c", "exit 0"}})
	if !errors.Is(err, ErrArtifactMismatch) || c != nil {
		t.Fatalf("%v %v", c, err)
	}
	if runs := runLines(t, root); len(runs) != 0 {
		t.Fatalf("nothing may be created or started: %q", runs)
	}
}

func TestPodmanExpectedImageAbsentIsNotAMismatch(t *testing.T) {
	p, root := newTestPodman(t)
	setTestImage(t, "example.test/other:1", "")
	c, err := p.Launch(context.Background(), Spec{Name: "e3", Program: "example.test/exec:1", Store: "work", Timeout: time.Minute,
		Expected: ociExpected(testDigest), Argv: []string{"sh", "-c", "exit 0"}})
	if err == nil || errors.Is(err, ErrArtifactMismatch) || !errors.Is(err, ErrDidNotLaunch) || c != nil {
		t.Fatalf("%v %v", c, err)
	}
	if runs := runLines(t, root); len(runs) != 0 {
		t.Fatalf("%q", runs)
	}
}

func TestPodmanNilExpectedIsUnchanged(t *testing.T) {
	p, root := newTestPodman(t)
	c, err := p.Launch(context.Background(), Spec{Name: "e4", Program: "example.test/exec:1", Store: "work", Timeout: time.Minute,
		Argv: []string{"sh", "-c", "exit 0"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, l := range readLog(t, root) {
		if strings.HasPrefix(l, "image ") {
			t.Fatalf("no inspect without Expected: %q", l)
		}
	}
	if runs := runLines(t, root); len(runs) != 1 || !strings.Contains(runs[0], " example.test/exec:1 ") {
		t.Fatalf("%q", runs)
	}
	if k, v, ok := c.RanArtifact(); ok || k != "" || v != nil {
		t.Fatalf("%q %v %v", k, v, ok)
	}
}

func TestPodmanExpectedOfAnotherKindFailsClosed(t *testing.T) {
	p, root := newTestPodman(t)
	setTestImage(t, "example.test/exec:1", "")
	c, err := p.Launch(context.Background(), Spec{Name: "e5", Program: "example.test/exec:1", Store: "work", Timeout: time.Minute,
		Expected: &ExpectedArtifact{Kind: "host-program", Values: []string{testDigest}}, Argv: []string{"sh", "-c", "exit 0"}})
	if !errors.Is(err, ErrArtifactMismatch) || c != nil || len(runLines(t, root)) != 0 {
		t.Fatalf("%v %v", c, err)
	}
}
