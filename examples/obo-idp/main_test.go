package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// newTestIDP serves an idp over httptest; the issuer is the server's own URL.
func newTestIDP(t *testing.T, tokenLog *bytes.Buffer) (*idp, *httptest.Server) {
	t.Helper()
	var p *idp
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { p.handler().ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	// A nil *bytes.Buffer must become a nil io.Writer, not an interface
	// holding a nil pointer (which idp would then write to).
	var log io.Writer
	if tokenLog != nil {
		log = tokenLog
	}
	var err error
	p, err = newIDP(srv.URL, "agenthof-broker", "shh secret", []string{"https://obo-upstream.example"},
		"urn:ietf:params:oauth:token-type:id_token", time.Hour, log)
	if err != nil {
		t.Fatalf("newIDP: %v", err)
	}
	return p, srv
}

func mint(t *testing.T, srv *httptest.Server, body map[string]any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	resp, err := srv.Client().Post(srv.URL+"/mint", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// TestMintedTokenVerifiesWithARealOIDCClient: the discovery document and
// JWKS are what a real relying party needs — go-oidc, the same library
// Agenthof uses inbound, verifies a minted token against them.
func TestMintedTokenVerifiesWithARealOIDCClient(t *testing.T) {
	_, srv := newTestIDP(t, nil)
	status, out := mint(t, srv, map[string]any{"sub": "u-dana", "email": "dana@example.com", "groups": []string{"obo-users"}, "aud": "agenthof"})
	if status != http.StatusOK {
		t.Fatalf("mint status = %d", status)
	}
	token, _ := out["token"].(string)
	if token == "" {
		t.Fatal("no token minted")
	}
	ctx := oidc.ClientContext(context.Background(), srv.Client())
	provider, err := oidc.NewProvider(ctx, srv.URL)
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	idToken, err := provider.Verifier(&oidc.Config{ClientID: "agenthof"}).Verify(ctx, token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	var claims struct {
		Email  string   `json:"email"`
		Groups []string `json:"groups"`
	}
	if err := idToken.Claims(&claims); err != nil {
		t.Fatal(err)
	}
	if idToken.Subject != "u-dana" || claims.Email != "dana@example.com" || len(claims.Groups) != 1 || claims.Groups[0] != "obo-users" {
		t.Fatalf("claims: sub=%q email=%q groups=%v", idToken.Subject, claims.Email, claims.Groups)
	}
}

func TestMintRejectsBadRequests(t *testing.T) {
	_, srv := newTestIDP(t, nil)
	if status, _ := mint(t, srv, map[string]any{"aud": "agenthof"}); status != http.StatusBadRequest {
		t.Fatalf("mint without sub: status = %d, want 400", status)
	}
	resp, err := srv.Client().Get(srv.URL + "/mint")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /mint: status = %d, want 405", resp.StatusCode)
	}
}

func TestVerifyRejectsForeignAndExpiredTokens(t *testing.T) {
	p, srv := newTestIDP(t, nil)
	other, otherSrv := newTestIDP(t, nil)
	foreign, err := other.sign(map[string]any{"iss": otherSrv.URL, "sub": "u", "aud": "agenthof", "exp": time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.verify(foreign); err == nil {
		t.Fatal("a token signed by another key must not verify")
	}
	expired, err := p.sign(map[string]any{"iss": srv.URL, "sub": "u", "aud": "agenthof", "exp": time.Now().Add(-time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.verify(expired); err == nil {
		t.Fatal("an expired token must not verify")
	}
	if _, err := p.verify("garbage"); err == nil {
		t.Fatal("garbage must not verify")
	}
	good, err := p.sign(map[string]any{"iss": srv.URL, "sub": "u-dana", "aud": "agenthof", "exp": time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := p.verify(good)
	if err != nil || claims["sub"] != "u-dana" {
		t.Fatalf("own token must verify: claims=%v err=%v", claims, err)
	}
	if strings.Count(good, ".") != 2 {
		t.Fatal("not a compact JWT")
	}
}
