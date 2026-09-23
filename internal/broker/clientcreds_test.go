package broker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newTokenEndpoint(t *testing.T, mints *int32, token string, expiresIn int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(mints, 1)
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
			t.Errorf("content-type = %q", ct)
		}
		user, pass, ok := r.BasicAuth()
		if !ok {
			t.Error("missing Basic auth")
		}
		// RFC 6749 §2.3.1: client id/secret are form-urlencoded before Basic.
		if u, _ := url.QueryUnescape(user); u != "client-abc" {
			t.Errorf("client id = %q", u)
		}
		if p, _ := url.QueryUnescape(pass); p != "shh secret" {
			t.Errorf("client secret = %q", p)
		}
		_ = r.ParseForm()
		if g := r.Form.Get("grant_type"); g != "client_credentials" {
			t.Errorf("grant_type = %q", g)
		}
		if s := r.Form.Get("scope"); s != "mcp.read mcp.call" {
			t.Errorf("scope = %q", s)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": token, "token_type": "Bearer", "expires_in": expiresIn,
		})
	}))
}

func ccRef(tokenURL string) CredentialRef {
	return CredentialRef{
		ResourceID: "github-mcp", Source: "static_env", Grant: "client_credentials",
		ClientAuth: "client_secret_basic", Issuer: "https://id.example.com",
		TokenURL: tokenURL, Scope: "mcp.read mcp.call",
		ClientIDEnv: "CC_ID", ClientSecretEnv: "CC_SECRET",
	}
}

func TestClientCredentialsMint(t *testing.T) {
	t.Setenv("CC_ID", "client-abc")
	t.Setenv("CC_SECRET", "shh secret") // space exercises form-urlencoding
	var mints int32
	srv := newTokenEndpoint(t, &mints, "minted-xyz", 3600)
	defer srv.Close()

	b := NewClientCredentials(srv.Client())
	got, err := b.Resolve(context.Background(), ccRef(srv.URL))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "minted-xyz" {
		t.Fatalf("token = %q, want minted-xyz", got)
	}
}

func TestClientCredentialsCacheHit(t *testing.T) {
	t.Setenv("CC_ID", "client-abc")
	t.Setenv("CC_SECRET", "shh secret")
	var mints int32
	srv := newTokenEndpoint(t, &mints, "minted-xyz", 3600)
	defer srv.Close()

	b := NewClientCredentials(srv.Client())
	for i := 0; i < 2; i++ {
		if _, err := b.Resolve(context.Background(), ccRef(srv.URL)); err != nil {
			t.Fatalf("Resolve #%d: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&mints); got != 1 {
		t.Fatalf("mints = %d, want 1 (second resolve should hit cache)", got)
	}
}

func TestClientCredentialsRefreshOnExpiry(t *testing.T) {
	t.Setenv("CC_ID", "client-abc")
	t.Setenv("CC_SECRET", "shh secret")
	var mints int32
	srv := newTokenEndpoint(t, &mints, "minted-xyz", 60)
	defer srv.Close()

	now := time.Unix(1_000_000, 0)
	b := NewClientCredentials(srv.Client())
	b.Now = func() time.Time { return now }

	if _, err := b.Resolve(context.Background(), ccRef(srv.URL)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(90 * time.Second) // past 60s expiry
	if _, err := b.Resolve(context.Background(), ccRef(srv.URL)); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&mints); got != 2 {
		t.Fatalf("mints = %d, want 2 (expired token should re-mint)", got)
	}
}

func TestClientCredentialsShortLifetimeStillCaches(t *testing.T) {
	// expires_in = 10 is well under the 30s refreshMargin ceiling; the
	// effective margin must fall back to 10% of lifetime (1s) so the token is
	// still cacheable instead of missing the cache on every resolve.
	t.Setenv("CC_ID", "client-abc")
	t.Setenv("CC_SECRET", "shh secret")
	var mints int32
	srv := newTokenEndpoint(t, &mints, "minted-xyz", 10)
	defer srv.Close()

	now := time.Unix(1_000_000, 0)
	b := NewClientCredentials(srv.Client())
	b.Now = func() time.Time { return now }

	for i := 0; i < 2; i++ {
		if _, err := b.Resolve(context.Background(), ccRef(srv.URL)); err != nil {
			t.Fatalf("Resolve #%d: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&mints); got != 1 {
		t.Fatalf("mints = %d, want 1 (short-lived token should still cache within its margin)", got)
	}
}

func TestClientCredentialsNoCacheWhenExpiresInAbsent(t *testing.T) {
	t.Setenv("CC_ID", "client-abc")
	t.Setenv("CC_SECRET", "shh secret")
	var mints int32
	srv := newTokenEndpoint(t, &mints, "minted-xyz", 0) // no usable lifetime
	defer srv.Close()

	b := NewClientCredentials(srv.Client())
	for i := 0; i < 2; i++ {
		if _, err := b.Resolve(context.Background(), ccRef(srv.URL)); err != nil {
			t.Fatalf("Resolve #%d: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&mints); got != 2 {
		t.Fatalf("mints = %d, want 2 (absent expires_in must not cache)", got)
	}
}

func TestClientCredentialsErrorHidesSecrets(t *testing.T) {
	t.Setenv("CC_ID", "client-abc")
	t.Setenv("CC_SECRET", "shh secret")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"shh secret was wrong"}`))
	}))
	defer srv.Close()

	b := NewClientCredentials(srv.Client())
	_, err := b.Resolve(context.Background(), ccRef(srv.URL))
	if err == nil {
		t.Fatal("expected error on 401")
	}
	msg := err.Error()
	if strings.Contains(msg, "shh secret") {
		t.Fatalf("error leaked a secret / description: %q", msg)
	}
	if !strings.Contains(msg, "invalid_client") || !strings.Contains(msg, "github-mcp") {
		t.Fatalf("error should name the RFC error code and resource: %q", msg)
	}
}

func TestClientCredentialsRejectsNonBearerTokenType(t *testing.T) {
	// RFC 6749 §7.1: a client must not use a token type it doesn't understand.
	t.Setenv("CC_ID", "client-abc")
	t.Setenv("CC_SECRET", "shh secret")
	const secretToken = "should-never-appear-in-error-xyz"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": secretToken, "token_type": "mac", "expires_in": 3600,
		})
	}))
	defer srv.Close()

	b := NewClientCredentials(srv.Client())
	_, err := b.Resolve(context.Background(), ccRef(srv.URL))
	if err == nil {
		t.Fatal("expected error for unsupported token_type")
	}
	msg := err.Error()
	if strings.Contains(msg, secretToken) {
		t.Fatalf("error leaked the access token: %q", msg)
	}
	if !strings.Contains(msg, "mac") || !strings.Contains(msg, "github-mcp") {
		t.Fatalf("error should name the unexpected token_type and resource: %q", msg)
	}
}
