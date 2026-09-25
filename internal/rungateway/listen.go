package rungateway

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/agenthof/agenthof/internal/config"
)

// listenGateway binds a run-unique Unix socket under dir and returns the
// listener plus the unix:// URL the agent must dial. The filename embeds runID
// plus a random nonce so concurrent runs and repeated steps never collide.
func listenGateway(dir, runID string) (net.Listener, string, error) {
	nonce := make([]byte, 4)
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", fmt.Errorf("socket nonce: %w", err)
	}
	path := filepath.Join(dir, fmt.Sprintf("gw-%s-%s.sock", runID, hex.EncodeToString(nonce)))
	ln, err := listenUnix(path)
	if err != nil {
		return nil, "", err
	}
	return ln, config.UnixScheme + path, nil
}

// listenUnix listens on a Unix socket at path, removing any file already there
// first (net.Listen fails if a file exists at the path, even one no process is
// listening on). Because listenGateway embeds a fresh random nonce per call,
// this guards only the vanishingly unlikely nonce collision — orphaned sockets
// from a process killed before Stop() keep their old nonce and are swept by the
// refbox recipe (1b), not here. The listener unlinks its socket on Close.
func listenUnix(path string) (net.Listener, error) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("remove stale socket %q: %w", path, err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen unix %q: %w", path, err)
	}
	return ln, nil
}
