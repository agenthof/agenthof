package identity

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/identity/oidctest"
)

// countingTransport counts requests whose URL contains needle.
type countingTransport struct {
	needle string
	hits   atomic.Int32
	next   http.RoundTripper
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.Contains(r.URL.String(), c.needle) {
		c.hits.Add(1)
	}
	return c.next.RoundTrip(r)
}

func TestCachedOIDCDiscoversOnce(t *testing.T) {
	key := oidctest.NewKey(t)
	srv := oidctest.NewServer(t, key)
	ct := &countingTransport{needle: "/.well-known/openid-configuration", next: http.DefaultTransport}
	c := NewCachedOIDC(context.Background(), OIDC{IssuerURL: srv.URL, ClientID: "agenthof", HTTP: &http.Client{Transport: ct}})
	tok := oidctest.MintToken(t, key, map[string]any{"iss": srv.URL, "aud": "agenthof", "exp": time.Now().Add(time.Hour).Unix(), "sub": "u-1", "email": "dana@example.com"})
	for range 3 {
		inv, err := c.Authenticate(context.Background(), tok)
		if err != nil || inv.Subject != "dana@example.com" || inv.Method != "oidc" {
			t.Fatalf("inv=%+v err=%v", inv, err)
		}
	}
	if n := ct.hits.Load(); n != 1 {
		t.Fatalf("discovery ran %d times, want once", n)
	}
}

func TestCachedOIDCNeverDialsTheTokensIssuer(t *testing.T) {
	key := oidctest.NewKey(t)
	configured := oidctest.NewServer(t, key)
	var attackerHits atomic.Int32
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attackerHits.Add(1)
		http.Error(w, "nope", http.StatusTeapot)
	}))
	t.Cleanup(attacker.Close)
	c := NewCachedOIDC(context.Background(), OIDC{IssuerURL: configured.URL, ClientID: "agenthof", HTTP: configured.Client()})
	// Signed by the configured issuer's key but claiming the attacker as
	// issuer: the only way to "verify" it is to fetch the attacker's keys.
	tok := oidctest.MintToken(t, key, map[string]any{"iss": attacker.URL, "aud": "agenthof", "exp": time.Now().Add(time.Hour).Unix(), "sub": "u-1"})
	_, err := c.Authenticate(context.Background(), tok)
	if err == nil {
		t.Fatal("a token for another issuer must not verify")
	}
	if errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("a bad token is the token's fault, not the provider's: %v", err)
	}
	if attackerHits.Load() != 0 {
		t.Fatalf("the token's iss was dialed %d times; the provider must be looked up by the CONFIGURED issuer only", attackerHits.Load())
	}
}

func TestCachedOIDCProviderDownIsUnavailableAndNotCached(t *testing.T) {
	key := oidctest.NewKey(t)
	real := oidctest.NewServer(t, key)
	var down atomic.Bool
	down.Store(true)
	gate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		// Proxy discovery to the real issuer but keep OUR URL as the issuer.
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"issuer":"` + gateURL(r) + `","jwks_uri":"` + real.URL + `/keys","id_token_signing_alg_values_supported":["RS256"]}`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(gate.Close)
	c := NewCachedOIDC(context.Background(), OIDC{IssuerURL: gate.URL, ClientID: "agenthof", HTTP: gate.Client()})
	tok := oidctest.MintToken(t, key, map[string]any{"iss": gate.URL, "aud": "agenthof", "exp": time.Now().Add(time.Hour).Unix(), "sub": "u-1"})
	_, err := c.Authenticate(context.Background(), tok)
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("err = %v, want ErrProviderUnavailable while discovery fails", err)
	}
	down.Store(false)
	if _, err := c.Authenticate(context.Background(), tok); err != nil {
		t.Fatalf("a failed discovery must not be cached; after recovery: %v", err)
	}
}

// gateURL rebuilds the httptest server's own URL from the request so the
// discovery document names the gate as its issuer.
func gateURL(r *http.Request) string { return "http://" + r.Host }

func TestCachedOIDCSurvivesACancelledRequestContext(t *testing.T) {
	key := oidctest.NewKey(t)
	srv := oidctest.NewServer(t, key)
	c := NewCachedOIDC(context.Background(), OIDC{IssuerURL: srv.URL, ClientID: "agenthof", HTTP: srv.Client()})
	tok := oidctest.MintToken(t, key, map[string]any{"iss": srv.URL, "aud": "agenthof", "exp": time.Now().Add(time.Hour).Unix(), "sub": "u-1"})
	dead, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = c.Authenticate(dead, tok) // the first request's context dies; the cache must not die with it
	if _, err := c.Authenticate(context.Background(), tok); err != nil {
		t.Fatalf("a later call with a live context must verify: %v", err)
	}
}
