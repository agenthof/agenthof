package rungateway

import "fmt"

// This file is a deliberate hand-mirror of deploy/internal/refrunner/fsnative.go.
// internal/ and deploy/ do not import each other, so the allow-list below is
// duplicated rather than shared (the same reason the private-directory gate
// exists twice, as refrunner.Listen and rungateway.CheckPrivateDir). KEEP THE
// ALLOW-LISTS IDENTICAL: a change to one set of magics must be made to the other
// in the same commit.

// Filesystem magic numbers (statfs f_type) for the local, kernel-native
// filesystems the gateway socket directory may live on. Values are from the
// Linux UAPI header linux/magic.h. They are declared here, GOOS-neutral, so
// classify is unit-testable on any host; a Linux-only test pins each one to the
// authoritative golang.org/x/sys/unix constant.
const (
	ext4Magic      uint32 = 0xEF53     // EXT4_SUPER_MAGIC (also ext2/ext3)
	xfsMagic       uint32 = 0x58465342 // XFS_SUPER_MAGIC
	btrfsMagic     uint32 = 0x9123683E // BTRFS_SUPER_MAGIC
	tmpfsMagic     uint32 = 0x01021994 // TMPFS_MAGIC
	overlayfsMagic uint32 = 0x794C7630 // OVERLAYFS_SUPER_MAGIC
	f2fsMagic      uint32 = 0xF2F52010 // F2FS_SUPER_MAGIC
	zfsMagic       uint32 = 0x2FC12FC1 // ZFS_SUPER_MAGIC (OpenZFS); not in x/sys/unix, so TestMagicsMatchUnix cannot pin it
	// bcachefs is intentionally excluded for now: niche, and not in x/sys/unix.
)

// nativeMagics is the allow-list. Anything not named here (9p/v9fs, cifs/smb,
// FUSE, virtiofs, NFS, ...) is a bridged or remote filesystem whose Unix-socket
// semantics are not the kernel's own, so it is refused.
var nativeMagics = map[uint32]struct{}{
	ext4Magic:      {},
	xfsMagic:       {},
	btrfsMagic:     {},
	tmpfsMagic:     {},
	overlayfsMagic: {},
	f2fsMagic:      {},
	zfsMagic:       {},
}

// classify returns nil if the filesystem magic is on the native allow-list,
// otherwise an error naming the magic.
func classify(magic uint32) error {
	if _, ok := nativeMagics[magic]; ok {
		return nil
	}
	return fmt.Errorf("rungateway: socket dir is on a non-native filesystem (fs magic %#x); place it on the host's local disk (ext4/xfs/btrfs/tmpfs/overlay/f2fs/zfs), not a bridged mount such as WSL2 /mnt", magic)
}
