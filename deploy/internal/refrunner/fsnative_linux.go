//go:build linux

package refrunner

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// CheckNativeFS refuses a directory that is not on a kernel-native local
// filesystem (see classify). The 0700/owner gate on the socket directory is
// only meaningful where the kernel itself enforces it; a bridged mount such as
// WSL2's 9p /mnt does not.
func CheckNativeFS(dir string) error {
	var s unix.Statfs_t
	if err := unix.Statfs(dir, &s); err != nil {
		return fmt.Errorf("refrunner: statfs %q: %w", dir, err)
	}
	// Statfs_t.Type is a signed integer whose width varies by arch; uint32 holds
	// every fs magic we classify.
	if err := classify(uint32(s.Type)); err != nil {
		return fmt.Errorf("%s: %w", dir, err)
	}
	return nil
}
