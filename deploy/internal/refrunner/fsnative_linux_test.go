//go:build linux

package refrunner

import (
	"testing"

	"golang.org/x/sys/unix"
)

// TestMagicsMatchUnix pins each hardcoded allow-list value to the authoritative
// golang.org/x/sys/unix constant, so a hand-typed number cannot drift.
func TestMagicsMatchUnix(t *testing.T) {
	for name, c := range map[string]struct{ got, want uint32 }{
		"ext4":    {ext4Magic, uint32(unix.EXT4_SUPER_MAGIC)},
		"xfs":     {xfsMagic, uint32(unix.XFS_SUPER_MAGIC)},
		"btrfs":   {btrfsMagic, uint32(unix.BTRFS_SUPER_MAGIC)},
		"tmpfs":   {tmpfsMagic, uint32(unix.TMPFS_MAGIC)},
		"overlay": {overlayfsMagic, uint32(unix.OVERLAYFS_SUPER_MAGIC)},
		"f2fs":    {f2fsMagic, uint32(unix.F2FS_SUPER_MAGIC)},
		// zfs is intentionally not pinned: golang.org/x/sys/unix does not define
		// ZFS_SUPER_MAGIC (verified against OpenZFS include/sys/fs/zfs.h instead).
		// bcachefs is intentionally excluded from the allow-list for now.
	} {
		if c.got != c.want {
			t.Errorf("%s: magic = %#x, want %#x", name, c.got, c.want)
		}
	}
}
