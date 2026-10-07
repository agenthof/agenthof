package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/identity/oidctest"
)

// testOIDCServer and mintToken delegate to the exported oidctest package
// so the other test suites (cmd/agenthof, internal/serve) mint the same
// tokens; the names stay so the call sites below read as before.
func testOIDCServer(t *testing.T, key *rsa.PrivateKey) *httptest.Server {
	return oidctest.NewServer(t, key)
}

func mintToken(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	return oidctest.MintToken(t, key, claims)
}

func TestOIDCAuthenticate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	srv := testOIDCServer(t, key)

	o := OIDC{IssuerURL: srv.URL, ClientID: "agenthof", HTTP: srv.Client()}
	ctx := context.Background()

	t.Run("valid token", func(t *testing.T) {
		token := mintToken(t, key, map[string]any{
			"iss":    srv.URL,
			"aud":    "agenthof",
			"exp":    time.Now().Add(time.Hour).Unix(),
			"sub":    "u-123",
			"email":  "dana@example.com",
			"groups": []string{"engineering", "finance"},
		})
		inv, err := o.Authenticate(ctx, token)
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		want := Invoker{
			Subject: "dana@example.com",
			Issuer:  srv.URL,
			Method:  "oidc",
			Groups:  []string{"engineering", "finance"},
		}
		if !reflect.DeepEqual(inv, want) {
			t.Fatalf("got %+v, want %+v", inv, want)
		}
	})

	t.Run("no email claim falls back to subject", func(t *testing.T) {
		token := mintToken(t, key, map[string]any{
			"iss": srv.URL,
			"aud": "agenthof",
			"exp": time.Now().Add(time.Hour).Unix(),
			"sub": "u-123",
		})
		inv, err := o.Authenticate(ctx, token)
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if inv.Subject != "u-123" {
			t.Fatalf("got subject %q, want u-123", inv.Subject)
		}
		if inv.Groups != nil {
			t.Fatalf("got groups %+v, want nil", inv.Groups)
		}
	})

	t.Run("expired token errors", func(t *testing.T) {
		token := mintToken(t, key, map[string]any{
			"iss": srv.URL,
			"aud": "agenthof",
			"exp": time.Now().Add(-time.Hour).Unix(),
			"sub": "u-123",
		})
		_, err := o.Authenticate(ctx, token)
		if err == nil {
			t.Fatal("expected error for expired token")
		}
		if strings.Contains(err.Error(), token) {
			t.Fatalf("error must not contain raw token: %v", err)
		}
	})

	t.Run("wrong audience errors", func(t *testing.T) {
		token := mintToken(t, key, map[string]any{
			"iss": srv.URL,
			"aud": "other",
			"exp": time.Now().Add(time.Hour).Unix(),
			"sub": "u-123",
		})
		_, err := o.Authenticate(ctx, token)
		if err == nil {
			t.Fatal("expected error for wrong audience")
		}
	})

	t.Run("garbage token errors", func(t *testing.T) {
		_, err := o.Authenticate(ctx, "garbage")
		if err == nil {
			t.Fatal("expected error for garbage token")
		}
	})

	t.Run("no groups claim yields nil groups", func(t *testing.T) {
		token := mintToken(t, key, map[string]any{
			"iss":   srv.URL,
			"aud":   "agenthof",
			"exp":   time.Now().Add(time.Hour).Unix(),
			"sub":   "u-123",
			"email": "dana@example.com",
		})
		inv, err := o.Authenticate(ctx, token)
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if inv.Groups != nil {
			t.Fatalf("got groups %+v, want nil", inv.Groups)
		}
	})
}

// TestOIDCAuthenticateAudience covers the additive resource-server audience.
// (a) a token audienced to neither ClientID nor Audience is rejected with a
// fixed message; (b) with Audience unset, behaviour is exactly as before:
// only ClientID is accepted; (c) a token audienced only to Audience is
// accepted; and ClientID keeps working when Audience is set.
func TestOIDCAuthenticateAudience(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	srv := testOIDCServer(t, key)
	ctx := context.Background()
	const resourceAud = "https://agenthof.example/api"
	mint := func(aud any) string {
		return mintToken(t, key, map[string]any{
			"iss": srv.URL, "aud": aud, "exp": time.Now().Add(time.Hour).Unix(), "sub": "u-123",
		})
	}
	withAud := OIDC{IssuerURL: srv.URL, ClientID: "agenthof", Audience: resourceAud, HTTP: srv.Client()}
	withoutAud := OIDC{IssuerURL: srv.URL, ClientID: "agenthof", HTTP: srv.Client()}

	t.Run("a: aud matching neither is rejected", func(t *testing.T) {
		_, err := withAud.Authenticate(ctx, mint("other"))
		if err == nil {
			t.Fatal("expected error for a token audienced to neither client id nor audience")
		}
		if strings.Contains(err.Error(), "other") {
			t.Fatalf("error must not echo the token's audience: %v", err)
		}
		if !strings.Contains(err.Error(), "does not include the client id or the configured audience") {
			t.Fatalf("expected the fixed audience message, got: %v", err)
		}
	})

	t.Run("b: audience unset behaves as today", func(t *testing.T) {
		if _, err := withoutAud.Authenticate(ctx, mint(resourceAud)); err == nil {
			t.Fatal("with Audience unset, a token audienced only to the resource audience must be rejected")
		}
		inv, err := withoutAud.Authenticate(ctx, mint("agenthof"))
		if err != nil {
			t.Fatalf("with Audience unset, the client id must still be accepted: %v", err)
		}
		if inv.Subject != "u-123" {
			t.Fatalf("subject = %q", inv.Subject)
		}
	})

	t.Run("c: token audienced only to Audience is accepted", func(t *testing.T) {
		inv, err := withAud.Authenticate(ctx, mint(resourceAud))
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if inv.Subject != "u-123" || inv.Method != "oidc" {
			t.Fatalf("got %+v", inv)
		}
	})

	t.Run("d: an unset client id matches no audience", func(t *testing.T) {
		noClientID := OIDC{IssuerURL: srv.URL, Audience: resourceAud, HTTP: srv.Client()}
		_, err := noClientID.Authenticate(ctx, mint([]string{""}))
		if err == nil {
			t.Fatal("with ClientID unset, a token audienced to the empty string must be rejected")
		}
		if !strings.Contains(err.Error(), "does not include the client id or the configured audience") {
			t.Fatalf("expected the fixed audience message, got: %v", err)
		}
	})

	t.Run("client id still accepted when Audience is set", func(t *testing.T) {
		if _, err := withAud.Authenticate(ctx, mint("agenthof")); err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if _, err := withAud.Authenticate(ctx, mint([]string{"other", resourceAud})); err != nil {
			t.Fatalf("multi-valued aud containing the audience must be accepted: %v", err)
		}
	})
}
