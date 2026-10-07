package serve

import (
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/identity"
)

func TestHealthzIsUnauthenticatedAndLeaksNothing(t *testing.T) {
	ts := newTestServer(t, &fakeHost{}, fakeAuth{}, 1)
	resp, body := ts.do(t, http.MethodGet, "/healthz", "", nil)
	if resp.StatusCode != http.StatusOK || string(body) != "ok\n" {
		t.Fatalf("healthz = %d %q, want 200 \"ok\\n\"", resp.StatusCode, body)
	}
}

func TestUnauthenticatedRequestWritesNothingAndLoadsNothing(t *testing.T) {
	ts := newTestServer(t, &fakeHost{}, fakeAuth{}, 1)
	for _, token := range []string{"", "not-the-token"} {
		resp, body := ts.do(t, http.MethodGet, "/v1/runs", token, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("token %q: status %d, want 401", token, resp.StatusCode)
		}
		if string(body) != "unauthorized\n" {
			t.Fatalf("401 body must be the fixed string, got %q", body)
		}
	}
	if n := ts.host.prepared.Load(); n != 0 {
		t.Fatalf("Prepare ran %d times for unauthenticated requests", n)
	}
	if entries, err := os.ReadDir(ts.logDir); err == nil && len(entries) != 0 {
		t.Fatalf("an unauthenticated request wrote to the log dir: %v", entries)
	}
}

func TestProviderDownIs503(t *testing.T) {
	ts := newTestServer(t, &fakeHost{}, fakeAuth{err: identity.ErrProviderUnavailable}, 1)
	resp, _ := ts.do(t, http.MethodGet, "/v1/runs", "anything", nil)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503 when discovery fails", resp.StatusCode)
	}
}

func TestBearerIsNeverLogged(t *testing.T) {
	ts := newTestServer(t, &fakeHost{}, fakeAuth{}, 1)
	const secret = "secret-bearer-value-9f8e7d"
	ts.do(t, http.MethodGet, "/v1/runs", secret, nil)
	ts.do(t, http.MethodGet, "/v1/runs", goodToken, nil)
	if logs := ts.logs.String(); strings.Contains(logs, secret) || strings.Contains(logs, goodToken) {
		t.Fatalf("a bearer reached the operational log:\n%s", logs)
	}
}

func TestBearerParsing(t *testing.T) {
	for h, want := range map[string]bool{"Bearer abc": true, "bearer abc": true, "Bearer ": false, "Basic abc": false, "": false, "abc": false} {
		if _, ok := bearer(h); ok != want {
			t.Errorf("bearer(%q) ok = %v, want %v", h, ok, want)
		}
	}
}
