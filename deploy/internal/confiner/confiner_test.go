package confiner

import (
	"strings"
	"testing"
)

func TestReservedAndKnownTiers(t *testing.T) {
	for _, r := range []Tier{"none", "landlock", "wsl2", "microvm"} {
		if !Reserved(r) {
			t.Fatalf("%s must be reserved", r)
		}
	}
	for _, k := range []Tier{TierPodman, TierSeatbelt, "future-tier"} {
		if Reserved(k) {
			t.Fatalf("%s must not be reserved", k)
		}
	}
}

func TestValidToken(t *testing.T) {
	for _, ok := range []string{"podman", "seatbelt", "shared-host-scratch", "a", strings.Repeat("a", 40)} {
		if !ValidToken(ok) {
			t.Fatal(ok)
		}
	}
	for _, bad := range []string{"", "Podman", "a b", "a\n", "-x", "1x", strings.Repeat("a", 41)} {
		if ValidToken(bad) {
			t.Fatalf("%q must be rejected", bad)
		}
	}
}

func TestValidStoreName(t *testing.T) { // ".scratch" is the Seatbelt backend's own directory under store_root
	if !ValidStoreName("agenthof-work") || ValidStoreName(".scratch") || ValidStoreName("../x") || ValidStoreName("") {
		t.Fatal("store name shape")
	}
}
