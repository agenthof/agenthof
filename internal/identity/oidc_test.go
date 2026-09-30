package identity

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

// testOIDCServer spins up an httptest server that serves OIDC discovery and
// JWKS documents backed by the given RSA key, and returns the server plus a
// helper to mint hand-built RS256 JWTs signed by that key.
func testOIDCServer(t *testing.T, key *rsa.PrivateKey) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                srv.URL,
			"jwks_uri":                              srv.URL + "/keys",
			"authorization_endpoint":                srv.URL + "/auth",
			"token_endpoint":                        srv.URL + "/token",
			"response_types_supported":              []string{"id_token"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})

	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"kid": "test",
					"alg": "RS256",
					"use": "sig",
					"n":   n,
					"e":   "AQAB",
				},
			},
		})
	})

	return srv
}

// mintToken hand-builds an RS256-signed JWT from the given claims.
func mintToken(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()

	header := map[string]any{"alg": "RS256", "kid": "test", "typ": "JWT"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
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
