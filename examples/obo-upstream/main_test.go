package main

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
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func serveJWKS(t *testing.T, key *rsa.PrivateKey) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "kid": "t", "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": "AQAB",
		}}})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func mintRS256(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": "t", "typ": "JWT"})
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	in := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	d := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

type bearerRT struct {
	base  http.RoundTripper
	token string
}

func (b *bearerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	if b.token != "" {
		r.Header.Set("Authorization", "Bearer "+b.token)
	}
	return b.base.RoundTrip(r)
}

// callWhoami connects to the server as an MCP client presenting token and
// returns the tool's text and IsError flag.
func callWhoami(t *testing.T, srv *httptest.Server, token string) (string, bool) {
	t.Helper()
	ctx := context.Background()
	client := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "v0"}, nil)
	sess, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint: srv.URL, HTTPClient: &http.Client{Transport: &bearerRT{base: http.DefaultTransport, token: token}},
	}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = sess.Close() }()
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "whoami", Arguments: map[string]any{}})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	var parts []string
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			parts = append(parts, tc.Text)
		}
	}
	return strings.Join(parts, " "), res.IsError
}

func TestWhoamiEnforcesSignatureExpiryAndAudience(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := serveJWKS(t, key)
	keys := oidc.NewRemoteKeySet(context.Background(), jwks.URL+"/")
	const aud = "https://obo-upstream.example"
	server := newServer(keys, aud, time.Now)
	srv := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil))
	defer srv.Close()
	in := time.Now().Add(time.Hour).Unix()

	cases := []struct {
		name    string
		token   string
		want    string
		isError bool
	}{
		{"right audience", mintRS256(t, key, map[string]any{"sub": "u-dana", "aud": aud, "exp": in}), "acting as: u-dana", false},
		{"multi-valued audience containing this server", mintRS256(t, key, map[string]any{"sub": "u-dana", "aud": []string{"x", aud}, "exp": in}), "acting as: u-dana", false},
		{"wrong audience", mintRS256(t, key, map[string]any{"sub": "u-dana", "aud": "https://other.example", "exp": in}), "audience mismatch", true},
		{"foreign key", mintRS256(t, otherKey, map[string]any{"sub": "u-dana", "aud": aud, "exp": in}), "unauthorized", true},
		{"expired", mintRS256(t, key, map[string]any{"sub": "u-dana", "aud": aud, "exp": time.Now().Add(-time.Minute).Unix()}), "unauthorized", true},
		{"no bearer", "", "unauthorized", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			text, isErr := callWhoami(t, srv, c.token)
			if isErr != c.isError || !strings.Contains(text, c.want) {
				t.Fatalf("text=%q isError=%v, want %q isError=%v", text, isErr, c.want, c.isError)
			}
		})
	}
}
