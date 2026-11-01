//go:build linux

package confiner

import (
	"errors"
	"fmt"
	"io/fs"
	"syscall"
	"testing"
)

// An ownerStart error marks the owner GONE only when it says so definitively:
// an exited owner (zombie or dead), a /proc/<pid> that does not exist, or a
// read of it the kernel refused with ESRCH because the process went away
// under it. Any other error — a permission denial, an I/O error, a stat line
// that does not parse — leaves the owner's liveness undeterminable, and such
// an owner must never be reaped.
func TestOwnerGoneClassifiesErrors(t *testing.T) {
	gone := map[string]error{
		"exited":       errOwnerExited,
		"no proc dir":  fs.ErrNotExist,
		"wrapped":      fmt.Errorf("open /proc/7/stat: %w", syscall.ENOENT),
		"no such proc": syscall.ESRCH,
	}
	for name, err := range gone {
		if !ownerGone(err) {
			t.Errorf("%s (%v): not classified as gone", name, err)
		}
	}
	undeterminable := map[string]error{
		"permission": syscall.EACCES,
		"io":         syscall.EIO,
		"plain":      errors.New("io"),
		"parse":      fmt.Errorf("confiner: /proc/7/stat: no comm field"),
	}
	for name, err := range undeterminable {
		if ownerGone(err) {
			t.Errorf("%s (%v): classified as gone, but liveness is undeterminable", name, err)
		}
	}
}
