package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func exchange(t *testing.T, srv *httptest.Server, user, pass string, form url.Values) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(user), url.QueryEscape(pass))
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func exchangeForm(subject, audience string) url.Values {
	return url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:id_token"},
		"audience":           {audience},
	}
}

func TestExchangeIssuesTokenForSubject(t *testing.T) {
	var tokenLog bytes.Buffer
	p, srv := newTestIDP(t, &tokenLog)
	_, minted := mint(t, srv, map[string]any{"sub": "u-dana", "aud": "agenthof"})
	subject, _ := minted["token"].(string)

	status, out := exchange(t, srv, "agenthof-broker", "shh secret", exchangeForm(subject, "https://obo-upstream.example"))
	if status != http.StatusOK {
		t.Fatalf("status = %d body=%v", status, out)
	}
	if out["issued_token_type"] != "urn:ietf:params:oauth:token-type:access_token" || out["token_type"] != "Bearer" {
		t.Fatalf("RFC 8693 response shape: %v", out)
	}
	if exp, _ := out["expires_in"].(float64); exp != 3600 {
		t.Fatalf("expires_in = %v, want 3600", out["expires_in"])
	}
	access, _ := out["access_token"].(string)
	claims, err := p.verify(access)
	if err != nil {
		t.Fatalf("exchanged token must be decodable and signed by the issuer: %v", err)
	}
	if claims["sub"] != "u-dana" || claims["aud"] != "https://obo-upstream.example" {
		t.Fatalf("exchanged token must carry the subject's sub and the requested aud: %v", claims)
	}
	if access == subject {
		t.Fatal("the exchanged token must be a new token, not the subject token passed through")
	}
	var line struct {
		Sub, Aud, Token string
	}
	if err := json.Unmarshal(tokenLog.Bytes(), &line); err != nil || line.Token != access || line.Sub != "u-dana" || line.Aud != "https://obo-upstream.example" {
		t.Fatalf("token log line = %q (err %v)", tokenLog.String(), err)
	}
}

func TestExchangeRejections(t *testing.T) {
	_, srv := newTestIDP(t, nil)
	_, minted := mint(t, srv, map[string]any{"sub": "u-dana", "aud": "agenthof"})
	subject, _ := minted["token"].(string)
	good := func() url.Values { return exchangeForm(subject, "https://obo-upstream.example") }

	cases := []struct {
		name       string
		user, pass string
		form       url.Values
		status     int
		code       string
	}{
		{"wrong secret", "agenthof-broker", "nope", good(), http.StatusUnauthorized, "invalid_client"},
		{"unknown client", "someone-else", "shh secret", good(), http.StatusUnauthorized, "invalid_client"},
		{"wrong grant", "agenthof-broker", "shh secret", func() url.Values { f := good(); f.Set("grant_type", "client_credentials"); return f }(), http.StatusBadRequest, "unsupported_grant_type"},
		{"wrong subject type", "agenthof-broker", "shh secret", func() url.Values {
			f := good()
			f.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
			return f
		}(), http.StatusBadRequest, "invalid_request"},
		{"garbage subject", "agenthof-broker", "shh secret", exchangeForm("garbage", "https://obo-upstream.example"), http.StatusBadRequest, "invalid_grant"},
		{"unlisted audience", "agenthof-broker", "shh secret", exchangeForm(subject, "https://nowhere.example"), http.StatusBadRequest, "invalid_target"},
		{"missing audience", "agenthof-broker", "shh secret", exchangeForm(subject, ""), http.StatusBadRequest, "invalid_target"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			status, out := exchange(t, srv, c.user, c.pass, c.form)
			if status != c.status || out["error"] != c.code {
				t.Fatalf("status=%d error=%v, want %d %s", status, out["error"], c.status, c.code)
			}
			desc, _ := out["error_description"].(string)
			if !strings.Contains(desc, "never-in-a-ledger") {
				t.Fatalf("error_description must carry the sentinel a proof greps for: %q", desc)
			}
			if _, ok := out["access_token"]; ok {
				t.Fatal("a rejection must issue no token")
			}
		})
	}
}
