package rungateway

import "testing"

func TestClassifyAllowsNativeFilesystems(t *testing.T) {
	for _, m := range []uint32{ext4Magic, xfsMagic, btrfsMagic, tmpfsMagic, overlayfsMagic, f2fsMagic, zfsMagic} {
		if err := classify(m); err != nil {
			t.Errorf("magic %#x: want allowed, got %v", m, err)
		}
	}
}

func TestClassifyRefusesBridgedFilesystems(t *testing.T) {
	// v9fs (WSL2 /mnt 9p), cifs/smb, and a stand-in FUSE magic.
	for _, m := range []uint32{0x01021997, 0xFF534D42, 0xFE534D42, 0x65735546} {
		if err := classify(m); err == nil {
			t.Errorf("magic %#x: want refused, got nil", m)
		}
	}
}
