package identity

import "testing"

func TestStaticExplicit(t *testing.T) {
	inv := Static("dana@example.com")
	if inv.Subject != "dana@example.com" || inv.Method != "asserted" || inv.Issuer != "local" {
		t.Fatalf("%+v", inv)
	}
}

func TestStaticFallsBackToOSUser(t *testing.T) {
	t.Setenv("USER", "osuser")
	if inv := Static(""); inv.Subject != "osuser" {
		t.Fatalf("%+v", inv)
	}
	t.Setenv("USER", "")
	if inv := Static(""); inv.Subject != "unknown" {
		t.Fatalf("%+v", inv)
	}
}
