// Package refrunner holds what Agenthof's reference operator-side runtimes
// (refbridge, refexec) genuinely share: the 0700-directory-gated Unix socket
// listener, a serve-until-signalled loop, and the deploy-side copy of the
// runtime-attestation wire contract. Nothing here is imported by internal/
// and nothing here imports it: the two sides pin the same shapes by hand.
package refrunner

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

// Listen binds a runtime's Unix socket. The socket's DIRECTORY is the access
// gate: it must be mode 0700 and owned by the user the runtime runs as, so no
// other host user can traverse to the socket — and so there is no window
// between listen and chmod in which the socket is reachable. This is what
// "reachable only by Agenthof" means against other host users; against the
// agent it is the mount namespace (the directory is never mounted into an
// agent compartment) plus the compartment's lack of network. The socket file
// is set to 0600 as well, and a stale file from an earlier process is removed.
func Listen(path string) (net.Listener, error) {
	dir := filepath.Dir(path)
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("refrunner: socket dir: %w", err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("refrunner: socket dir %s is not a directory", dir)
	}
	if perm := fi.Mode().Perm(); perm != 0o700 {
		return nil, fmt.Errorf("refrunner: socket dir %s has mode %04o, want 0700 (only the user Agenthof runs as may reach the socket)", dir, perm)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return nil, fmt.Errorf("refrunner: socket dir %s is owned by uid %d, not the user this runtime runs as (uid %d)", dir, st.Uid, os.Getuid())
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("refrunner: remove stale socket: %w", err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("refrunner: listen: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("refrunner: chmod socket: %w", err)
	}
	return ln, nil
}
