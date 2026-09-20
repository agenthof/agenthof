package main

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"
)

// TestResolveInvokerMatrix is the brief's matrix on method (not subject —
// the test env has no stable USER): as-only asserts, and a --token with no
// issuer configured is a usage error.
func TestResolveInvokerMatrix(t *testing.T) {
	// A token exported in the ambient shell must not divert this
	// static-path case onto OIDC (mirrors the guard used throughout
	// main_test.go's static-path tests).
	t.Setenv("AGENTHOF_TOKEN", "")
	// neither -> asserted
	inv, aa, ref, ue, verr := resolveInvoker("dana@example.com", "eng", "")
	if inv.Method != "asserted" || ref || ue || aa != "" || verr != nil {
		t.Fatalf("as-only: %+v aa=%q ref=%v ue=%v verr=%v", inv, aa, ref, ue, verr)
	}
	if len(inv.Groups) != 1 || inv.Groups[0] != "eng" {
		t.Fatalf("groups=%v", inv.Groups)
	}
	// token set, issuer unset -> usage error
	t.Setenv("AGENTHOF_OIDC_ISSUER", "")
	_, _, _, ue, _ = resolveInvoker("", "", "sometoken")
	if !ue {
		t.Fatal("token without issuer must be a usage error")
	}
}

// TestResolveInvokerVerifiedToken covers the verified-token path: method
// "oidc", assertedAs carrying --as without overwriting the verified
// subject, and a nil verifyErr.
func TestResolveInvokerVerifiedToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	srv := cmdTestOIDCServer(t, key)
	token := cmdMintToken(t, key, map[string]any{
		"iss":   srv.URL,
		"aud":   "agenthof",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"sub":   "u-123",
		"email": "dana@example.com",
	})
	t.Setenv("AGENTHOF_OIDC_ISSUER", srv.URL)
	t.Setenv("AGENTHOF_OIDC_CLIENT_ID", "agenthof")

	inv, aa, ref, ue, verr := resolveInvoker("ignored-as", "ignored-groups", token)
	if ue || ref {
		t.Fatalf("unexpected refusal/usage error: ref=%v ue=%v", ref, ue)
	}
	if verr != nil {
		t.Fatalf("verifyErr = %v, want nil on a verified token", verr)
	}
	if inv.Method != "oidc" {
		t.Fatalf("Method = %q, want oidc: %+v", inv.Method, inv)
	}
	if inv.Subject != "dana@example.com" {
		t.Fatalf("Subject = %q, want dana@example.com (must not be overwritten by --as)", inv.Subject)
	}
	if aa != "ignored-as" {
		t.Fatalf("assertedAs = %q, want the --as value", aa)
	}
}

// TestResolveInvokerFailedToken covers the verification-failed path:
// refused=true, method "oidc-rejected", and a non-nil verifyErr.
func TestResolveInvokerFailedToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	srv := cmdTestOIDCServer(t, key)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	badToken := cmdMintToken(t, otherKey, map[string]any{
		"iss":   srv.URL,
		"aud":   "agenthof",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"sub":   "u-123",
		"email": "dana@example.com",
	})
	t.Setenv("AGENTHOF_OIDC_ISSUER", srv.URL)
	t.Setenv("AGENTHOF_OIDC_CLIENT_ID", "agenthof")

	inv, _, ref, ue, verr := resolveInvoker("", "", badToken)
	if ue {
		t.Fatal("bad token must not be a usage error")
	}
	if !ref {
		t.Fatal("bad token must be refused")
	}
	if verr == nil {
		t.Fatal("verifyErr must be non-nil on a failed token")
	}
	if inv.Subject != "(unverified)" || inv.Issuer != srv.URL || inv.Method != "oidc-rejected" {
		t.Fatalf("got %+v", inv)
	}
}
