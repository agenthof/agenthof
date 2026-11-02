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
	// Statfs_t.Type is int64 on Linux; the magics are 32-bit values.
	return classify(uint32(s.Type))
}
