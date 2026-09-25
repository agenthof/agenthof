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

// listenUnix listens on a Unix socket at path, removing any stale file first
// (net.Listen fails with "address already in use" if a file exists there even
// when nothing is listening — e.g. after a prior process was killed before
// Stop()). The listener unlinks the socket on Close.
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
