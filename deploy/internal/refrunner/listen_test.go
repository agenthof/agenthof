package refrunner

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// socketDir makes a short-pathed directory with the given mode. Short on
// purpose: Unix socket paths have a small OS length limit.
func socketDir(t *testing.T, mode os.FileMode) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "rrl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestListenRequires0700Dir(t *testing.T) {
	dir := socketDir(t, 0o755)
	_, err := Listen(filepath.Join(dir, "b.sock"))
	if err == nil || !strings.Contains(err.Error(), "mode 0755, want 0700") {
		t.Fatalf("err = %v, want a 0700 refusal naming the mode", err)
	}
}

func TestListenListensWith0600AndReplacesStale(t *testing.T) {
	dir := socketDir(t, 0o700)
	path := filepath.Join(dir, "b.sock")
	if err := os.WriteFile(path, []byte("stale"), 0o600); err != nil { // a leftover from a killed process
		t.Fatal(err)
	}
	ln, err := Listen(path)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %v, want a socket with 0600", fi.Mode())
	}
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()
}
