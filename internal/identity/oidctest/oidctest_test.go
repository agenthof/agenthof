package oidctest_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/identity/oidctest"
)

func TestServerServesDiscoveryForItself(t *testing.T) {
	key := oidctest.NewKey(t)
	srv := oidctest.NewServer(t, key)
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if doc.Issuer != srv.URL || doc.JWKSURI != srv.URL+"/keys" {
		t.Fatalf("discovery = %+v, want issuer %s", doc, srv.URL)
	}
	tok := oidctest.MintToken(t, key, map[string]any{"iss": srv.URL, "sub": "u"})
	if strings.Count(tok, ".") != 2 {
		t.Fatalf("not a compact JWT: %q", tok)
	}
}
