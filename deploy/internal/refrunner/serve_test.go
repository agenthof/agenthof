package refrunner

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestServeShutsDownOnSignalAndRemovesSocket(t *testing.T) {
	dir := socketDir(t, 0o700)
	path := filepath.Join(dir, "s.sock")
	ln, err := Listen(path)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	shut := make(chan struct{})
	stop := make(chan os.Signal, 1)
	errc := make(chan error, 1)
	go func() {
		errc <- serve(ln, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("ok"))
		}), slog.New(slog.DiscardHandler), func() { close(shut) }, stop)
	}()

	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}}
	resp, err := client.Get("http://runtime/")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "ok" {
		t.Fatalf("body = %q, want ok", body)
	}

	stop <- syscall.SIGTERM
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("serve returned %v, want nil on an orderly shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not return after SIGTERM")
	}
	select {
	case <-shut:
	default:
		t.Fatal("onShutdown did not run before serve returned")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("socket file still present after shutdown: %v", err)
	}
}
