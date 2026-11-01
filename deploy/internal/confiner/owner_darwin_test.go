//go:build darwin

package confiner

import (
	"errors"
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
)

// An ownerStart error marks the owner GONE only when it says so definitively:
// an exited owner, or a pid the kernel has no record for (which
// unix.SysctlKinfoProc reports as EIO from its size check, and the kernel
// itself names ESRCH). Any other error leaves the owner's liveness
// undeterminable, and such an owner must never be reaped.
func TestOwnerGoneClassifiesErrors(t *testing.T) {
	gone := map[string]error{
		"exited":       errOwnerExited,
		"no record":    unix.EIO,
		"wrapped":      fmt.Errorf("confiner: owner: %w", unix.EIO),
		"no such proc": unix.ESRCH,
	}
	for name, err := range gone {
		if !ownerGone(err) {
			t.Errorf("%s (%v): not classified as gone", name, err)
		}
	}
	undeterminable := map[string]error{
		"permission": unix.EPERM,
		"plain":      errors.New("io"),
		"invalid":    unix.EINVAL,
	}
	for name, err := range undeterminable {
		if ownerGone(err) {
			t.Errorf("%s (%v): classified as gone, but liveness is undeterminable", name, err)
		}
	}
}

// An owner whose start time cannot be read is treated as ALIVE, so its
// compartments are left in place: reaping a live sibling's compartment ends
// its command mid-flight, while leaving a leftover only defers cleanup to the
// next sweep.
func TestOwnerAliveWhenLivenessUndeterminable(t *testing.T) {
	self := mustSelfOwner(t)
	o := ownerRef{pid: self.pid, start: self.start, boot: self.boot}
	if !o.alive(self.boot) {
		t.Fatal("own stamp is not alive")
	}
	// Gone, definitively: no kernel record for the pid.
	if (ownerRef{pid: 2_000_000_000, start: 1, boot: self.boot}).alive(self.boot) {
		t.Fatal("a pid without a kernel record is alive")
	}
	if !(ownerRef{pid: 2_000_000_000, start: 1}).reapableBy(self) {
		t.Fatal("a pid without a kernel record is not reapable")
	}
}
