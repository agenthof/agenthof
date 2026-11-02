//go:build linux

package rungateway

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// nativeFS refuses a directory that is not on a kernel-native local filesystem
// (see classify). It checks nativeness only: the gateway socket is authenticated
// by a bearer token and its directory is mounted into the compartment by design,
// so no mode or owner gate applies here (contrast refrunner.Listen).
func nativeFS(dir string) error {
	var s unix.Statfs_t
	if err := unix.Statfs(dir, &s); err != nil {
		return fmt.Errorf("rungateway: statfs %q: %w", dir, err)
	}
	// Statfs_t.Type is a signed integer whose width varies by arch; uint32 holds
	// every fs magic we classify.
	if err := classify(uint32(s.Type)); err != nil {
		return fmt.Errorf("%s: %w", dir, err)
	}
	return nil
}
