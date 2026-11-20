//go:build darwin

package confiner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// hostProgramHash is the sha256:<hex> form of path's contents, computed here
// independently of the code under test.
func hostProgramHash(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// writeProgram writes an executable script; the body leaves its marks in the
// cwd (the store), so a test can tell whether it ever executed.
func writeProgram(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

func hostExpected(vals ...string) *ExpectedArtifact {
	return &ExpectedArtifact{Kind: "host-program", Values: vals}
}

func launchWait(t *testing.T, s *Seatbelt, spec Spec) (Compartment, Result) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := s.Launch(ctx, spec)
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	res, err := c.Wait(ctx)
	if err != nil {
		t.Fatalf("Wait: %v (output %q)", err, res.Output)
	}
	return c, res
}

func TestSeatbeltHostProgramInSetRunsAndReportsMeasuredHash(t *testing.T) {
	s := newTestSeatbelt(t, nil)
	mustCreateStore(t, s, "w")
	prog := writeProgram(t, t.TempDir(), "prog", `echo hi > ran`)
	h := hostProgramHash(t, prog)

	c, res := launchWait(t, s, Spec{Name: "refexec-01", Store: "w", Argv: []string{prog}, Expected: hostExpected(h)})
	if res.Exit != 0 {
		t.Fatalf("exit %d, output %q", res.Exit, res.Output)
	}
	mustExist(t, "the consented program ran", filepath.Join(s.StorePath("w"), "ran"))
	kind, vals, ok := c.RanArtifact()
	if kind != "host-program" || !ok || !slices.Equal(vals, []string{h}) {
		t.Fatalf("RanArtifact = %q %v %v, want host-program [%s] true", kind, vals, ok, h)
	}
}

func TestSeatbeltHostProgramNotInSetNeverExecs(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "sandbox-exec-ran")
	s := newTestSeatbelt(t, func(c *SeatbeltConfig) {
		c.SandboxExec = writeStub(t, fmt.Sprintf(`touch %q; exit 0`, marker))
	})
	mustCreateStore(t, s, "w")
	prog := writeProgram(t, t.TempDir(), "prog", `echo hi > ran`)
	other := "sha256:" + strings.Repeat("0", 64)

	c, err := s.Launch(context.Background(), Spec{Name: "refexec-01", Store: "w", Argv: []string{prog}, Expected: hostExpected(other)})
	if !errors.Is(err, ErrArtifactMismatch) || c != nil {
		t.Fatalf("Launch = %v, %v; want ErrArtifactMismatch and no compartment", c, err)
	}
	if errors.Is(err, ErrDidNotLaunch) {
		t.Fatalf("a mismatch must be distinct from ErrDidNotLaunch: %v", err)
	}
	mustNotExist(t, marker)
	mustNotExist(t, filepath.Join(s.StorePath("w"), "ran"))
	if ents, _ := os.ReadDir(s.cfg.PIDDir); len(ents) != 0 {
		t.Fatalf("a refused launch left %d PID records", len(ents))
	}
}

// The file hashed is the file exec'd: a symlink is resolved, so the hash is
// the target's, and retargeting the link at other bytes is refused.
func TestSeatbeltHostProgramSymlinkHashedAtResolvedTarget(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "args")
	// A recording sandbox-exec stub shows the path the real one would exec.
	s := newTestSeatbelt(t, func(c *SeatbeltConfig) {
		c.SandboxExec = writeStub(t, fmt.Sprintf(`printf '%%s\n' "${@: -1}" > %q; exit 0`, marker))
	})
	mustCreateStore(t, s, "w")
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := writeProgram(t, dir, "real", `echo real > ran`)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	h := hostProgramHash(t, target)

	c, _ := launchWait(t, s, Spec{Name: "refexec-01", Store: "w", Argv: []string{link}, Expected: hostExpected(h)})
	if _, vals, ok := c.RanArtifact(); !ok || !slices.Equal(vals, []string{h}) {
		t.Fatalf("RanArtifact = %v %v, want [%s]", vals, ok, h)
	}
	// The path handed to sandbox-exec is the resolved target, the very file hashed.
	got, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(got)) != target {
		t.Fatalf("sandbox-exec was handed %q, want the resolved target %q", got, target)
	}

	// Retarget the link at different bytes: the consented hash no longer matches.
	evil := writeProgram(t, dir, "evil", `echo evil > evilran`)
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(evil, link); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Launch(context.Background(), Spec{Name: "refexec-02", Store: "w", Argv: []string{link}, Expected: hostExpected(h)}); !errors.Is(err, ErrArtifactMismatch) {
		t.Fatalf("retargeted link: err = %v, want ErrArtifactMismatch", err)
	}
}

// The same link run for real: the resolved target executes under the real
// sandbox-exec.
func TestSeatbeltHostProgramSymlinkRunsResolvedTarget(t *testing.T) {
	s := newTestSeatbelt(t, nil)
	mustCreateStore(t, s, "w")
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := writeProgram(t, dir, "real", `echo real > ran`)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	_, res := launchWait(t, s, Spec{Name: "refexec-01", Store: "w", Argv: []string{link}, Expected: hostExpected(hostProgramHash(t, target))})
	if res.Exit != 0 {
		t.Fatalf("exit %d, output %q", res.Exit, res.Output)
	}
	mustExist(t, "the resolved target ran", filepath.Join(s.StorePath("w"), "ran"))
}

func TestSeatbeltNilExpectedUnchanged(t *testing.T) {
	s := newTestSeatbelt(t, nil)
	mustCreateStore(t, s, "w")
	prog := writeProgram(t, t.TempDir(), "prog", `echo hi > ran`)
	c, res := launchWait(t, s, Spec{Name: "refexec-01", Store: "w", Argv: []string{prog}})
	if res.Exit != 0 {
		t.Fatalf("exit %d, output %q", res.Exit, res.Output)
	}
	if k, v, ok := c.RanArtifact(); k != "" || v != nil || ok {
		t.Fatalf("RanArtifact = %q %v %v, want empty", k, v, ok)
	}
}

// The reported set is what was measured, not the consented set: extra
// consented values never show up in RanArtifact.
func TestSeatbeltHostProgramMeasuredNotEchoed(t *testing.T) {
	s := newTestSeatbelt(t, nil)
	mustCreateStore(t, s, "w")
	prog := writeProgram(t, t.TempDir(), "prog", `true`)
	h := hostProgramHash(t, prog)
	bogus := "sha256:" + strings.Repeat("a", 64)
	c, _ := launchWait(t, s, Spec{Name: "refexec-01", Store: "w", Argv: []string{prog}, Expected: hostExpected(bogus, h)})
	if _, vals, ok := c.RanArtifact(); !ok || !slices.Equal(vals, []string{h}) {
		t.Fatalf("RanArtifact = %v %v, want only the measured [%s]", vals, ok, h)
	}
}

func TestSeatbeltExpectedOfAnotherKindFailsClosed(t *testing.T) {
	s := newTestSeatbelt(t, nil)
	mustCreateStore(t, s, "w")
	prog := writeProgram(t, t.TempDir(), "prog", `echo hi > ran`)
	h := hostProgramHash(t, prog)
	_, err := s.Launch(context.Background(), Spec{Name: "refexec-01", Store: "w", Argv: []string{prog}, Expected: &ExpectedArtifact{Kind: "oci-image", Values: []string{h}}})
	if !errors.Is(err, ErrArtifactMismatch) {
		t.Fatalf("err = %v, want ErrArtifactMismatch", err)
	}
	mustNotExist(t, filepath.Join(s.StorePath("w"), "ran"))
}

// A bound program that cannot be read is refused before sandbox-exec runs and
// leaves no PID record.
func TestSeatbeltHostProgramUnreadableFailsClosed(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := "sha256:" + strings.Repeat("b", 64)
	unreadable := writeProgram(t, dir, "unreadable", `true`)
	if err := os.Chmod(unreadable, 0o100); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "gone"), dangling); err != nil {
		t.Fatal(err)
	}
	for name, prog := range map[string]string{"unreadable": unreadable, "dangling": dangling, "missing": filepath.Join(dir, "missing")} {
		t.Run(name, func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "sandbox-exec-ran")
			s := newTestSeatbelt(t, func(c *SeatbeltConfig) {
				c.SandboxExec = writeStub(t, fmt.Sprintf(`touch %q; exit 0`, marker))
			})
			mustCreateStore(t, s, "w")
			c, err := s.Launch(context.Background(), Spec{Name: "refexec-01", Store: "w", Argv: []string{prog}, Expected: hostExpected(h)})
			if c != nil || err == nil {
				t.Fatalf("Launch = %v, %v; want a refusal", c, err)
			}
			// An I/O failure is did-not-launch, never a mismatch: nothing ran.
			if !errors.Is(err, ErrDidNotLaunch) || errors.Is(err, ErrArtifactMismatch) {
				t.Fatalf("%s: err = %v, want ErrDidNotLaunch and not ErrArtifactMismatch", name, err)
			}
			mustNotExist(t, marker)
			if ents, _ := os.ReadDir(s.cfg.PIDDir); len(ents) != 0 {
				t.Fatalf("a refused launch left %d PID records", len(ents))
			}
		})
	}
}

// An empty consented set matches nothing: a bound launch is refused.
func TestSeatbeltHostProgramEmptyValuesRefused(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "sandbox-exec-ran")
	s := newTestSeatbelt(t, func(c *SeatbeltConfig) {
		c.SandboxExec = writeStub(t, fmt.Sprintf(`touch %q; exit 0`, marker))
	})
	mustCreateStore(t, s, "w")
	prog := writeProgram(t, t.TempDir(), "prog", `echo hi > ran`)
	for _, exp := range []*ExpectedArtifact{hostExpected(), {Kind: "host-program", Values: nil}} {
		c, err := s.Launch(context.Background(), Spec{Name: "refexec-01", Store: "w", Argv: []string{prog}, Expected: exp})
		if !errors.Is(err, ErrArtifactMismatch) || c != nil {
			t.Fatalf("Launch = %v, %v; want ErrArtifactMismatch", c, err)
		}
	}
	mustNotExist(t, marker)
}
