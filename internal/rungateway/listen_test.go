package rungateway

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/broker"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/engine"
)

// shortSockDir is a temp directory whose path fits in a Unix socket address.
// t.TempDir() on macOS is longer than the 104-byte sun_path cap once the
// socket filename is appended.
func shortSockDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "ah")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestListenGatewayReturnsUnixURL(t *testing.T) {
	dir := shortSockDir(t)
	ln, url, err := listenGateway(dir, "r-abc123")
	if err != nil {
		t.Fatalf("listenGateway: %v", err)
	}
	defer func() { _ = ln.Close() }()
	if !strings.HasPrefix(url, "unix://") {
		t.Fatalf("url = %q, want unix:// prefix", url)
	}
	sockPath := strings.TrimPrefix(url, "unix://")
	if filepath.Dir(sockPath) != dir {
		t.Fatalf("socket %q not under dir %q", sockPath, dir)
	}
	if _, err := os.Stat(sockPath); err != nil {
		t.Fatalf("socket file missing: %v", err)
	}
	if ln.Addr().Network() != "unix" {
		t.Fatalf("network = %q, want unix", ln.Addr().Network())
	}
}

func TestListenGatewayRemovesStaleSocket(t *testing.T) {
	dir := shortSockDir(t)
	stale := filepath.Join(dir, "gw-r-stale-0000.sock")
	if err := os.WriteFile(stale, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := listenUnix(stale)
	if err != nil {
		t.Fatalf("listenUnix over stale file: %v", err)
	}
	defer func() { _ = ln.Close() }()
	conn, err := net.Dial("unix", stale)
	if err != nil {
		t.Fatalf("dial fresh socket: %v", err)
	}
	_ = conn.Close()
}

func TestStartUnixSocketServesAuthedRequests(t *testing.T) {
	dir := shortSockDir(t)
	gw := New(config.GatewayConfig{RefboxSocketDir: dir}, ".", broker.StaticEnv{}, nil)
	url, token, err := gw.Start(engine.Binding{RunID: "r-udstest"}, config.AgentDef{Name: "a"}, func(engine.Event) {})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer gw.Stop()

	sockPath := strings.TrimPrefix(url, config.UnixScheme)
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
		},
	}}

	req, err := http.NewRequest(http.MethodPost, "http://agenthof/exec/authorize", strings.NewReader(`{"command":["x"]}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("authed request: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authed status = %d, want 200", resp.StatusCode)
	}

	req2, err := http.NewRequest(http.MethodPost, "http://agenthof/exec/authorize", strings.NewReader(`{"command":["x"]}`))
	if err != nil {
		t.Fatal(err)
	}
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("unauthed request: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp2.Body)
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthed status = %d, want 401", resp2.StatusCode)
	}
}

func TestStartTCPDefaultUnchanged(t *testing.T) {
	gw := New(config.GatewayConfig{}, ".", broker.StaticEnv{}, nil)
	url, _, err := gw.Start(engine.Binding{RunID: "r-tcp"}, config.AgentDef{Name: "a"}, func(engine.Event) {})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer gw.Stop()
	if !strings.HasPrefix(url, "http://127.0.0.1:") {
		t.Fatalf("default url = %q, want http://127.0.0.1: prefix", url)
	}
}

func TestStopRemovesSocketFile(t *testing.T) {
	dir := shortSockDir(t)
	gw := New(config.GatewayConfig{RefboxSocketDir: dir}, ".", broker.StaticEnv{}, nil)
	url, _, err := gw.Start(engine.Binding{RunID: "r-cleanup"}, config.AgentDef{Name: "a"}, func(engine.Event) {})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !strings.HasPrefix(url, config.UnixScheme) {
		t.Fatalf("url = %q, want unix://", url)
	}
	sockPath := strings.TrimPrefix(url, config.UnixScheme)
	gw.Stop()
	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Fatalf("socket file still present after Stop: err=%v", err)
	}
}
