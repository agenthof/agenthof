//go:build darwin

package main

import (
	"context"
	"os"
	"testing"

	"github.com/agenthof/agenthof/deploy/internal/confiner"
)

// On a macOS dev machine an unset confiner selects the OS default, Seatbelt.
// The hermetic stub must never inherit that: it builds the fake-podman
// backend directly, so a stub run cannot hand a compartment a real sandbox.
func TestStubConstructsPodmanOnDarwin(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	c := stubConfiner(execConfig{Confiner: ""}, exe)
	if c.Tier() != confiner.TierPodman {
		t.Fatalf("stub tier = %q, want %q (never %q)", c.Tier(), confiner.TierPodman, confiner.TierSeatbelt)
	}
	// The fake's `info` answers "linux true false", which the podman probe
	// accepts; a Seatbelt backend would have probed sandbox-exec instead.
	if err := c.Probe(context.Background()); err != nil {
		t.Fatalf("probe through the fake podman: %v", err)
	}
}
