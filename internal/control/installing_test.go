package control_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/ledger"
)

// TestInstallingAxes: the four accept/reject axes — outcome, hash, action,
// bootstrap — of the one shared "installing event" definition.
func TestInstallingAxes(t *testing.T) {
	const h = "sha256:abc"
	cases := []struct {
		name string
		e    control.DecodedEvent
		want bool
	}{
		{"apply success", control.DecodedEvent{Action: "apply", Outcome: "success", ConfigHash: h}, true},
		{"bootstrap apply success", control.DecodedEvent{Action: "apply", Outcome: "success", ConfigHash: h, Bootstrap: true}, true},
		{"disable success", control.DecodedEvent{Action: "disable", Agent: "coder", Outcome: "success", ConfigHash: h}, true},
		{"enable success", control.DecodedEvent{Action: "enable", Agent: "coder", Outcome: "success", ConfigHash: h}, true},
		{"bootstrap-era disable", control.DecodedEvent{Action: "disable", Agent: "coder", Outcome: "success", ConfigHash: h, Bootstrap: true}, false},
		{"bootstrap-era enable", control.DecodedEvent{Action: "enable", Agent: "coder", Outcome: "success", ConfigHash: h, Bootstrap: true}, false},
		{"apply rejected", control.DecodedEvent{Action: "apply", Outcome: "rejected", ConfigHash: h}, false},
		{"apply refused", control.DecodedEvent{Action: "apply", Outcome: "refused", ConfigHash: h}, false},
		{"disable refused", control.DecodedEvent{Action: "disable", Agent: "ghost", Outcome: "refused"}, false},
		{"apply success without hash", control.DecodedEvent{Action: "apply", Outcome: "success"}, false},
		{"repair success", control.DecodedEvent{Action: "repair", Outcome: "success"}, false},
		{"provision success with hash is not an install", control.DecodedEvent{Action: "provision", Outcome: "success", ConfigHash: h}, false},
		{"prune success is not an install", control.DecodedEvent{Action: "prune", Outcome: "success"}, false},
	}
	for _, c := range cases {
		if got := control.Installing(c.e); got != c.want {
			t.Errorf("%s: Installing = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestInstallingRoundTripsBothProducers: an apply and a flip written by Append
// decode to events the predicate accepts; a flip written with Bootstrap does not.
func TestInstallingRoundTripsBothProducers(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.jsonl")
	inv := identity.Static("dana@example.com")
	for _, e := range []control.Event{
		{Action: "apply", Outcome: "success", Invoker: inv, Witness: control.CaptureWitness(), ConfigHash: "sha256:aaa", Bootstrap: true},
		{Action: "disable", Agent: "coder", Outcome: "success", Invoker: inv, Witness: control.CaptureWitness(), ConfigHash: "sha256:bbb"},
		{Action: "enable", Agent: "coder", Outcome: "success", Invoker: inv, Witness: control.CaptureWitness(), ConfigHash: "sha256:ccc", Bootstrap: true},
	} {
		if _, err := control.Append(p, e); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != 3 || !strings.Contains(lines[2], `"action":"enable"`) || !strings.Contains(lines[2], `"bootstrap":true`) {
		t.Fatalf("the bootstrap-era flip must carry the marker on the wire:\n%s", raw)
	}
	if strings.Contains(lines[1], `"bootstrap"`) {
		t.Fatalf("an installed-path flip must omit the field entirely: %s", lines[1])
	}
	recs, _, verr := ledger.ReadVerify(p, ledger.Locked)
	if verr != nil {
		t.Fatal(verr)
	}
	want := []bool{true, true, false}
	for i, r := range recs {
		d, err := control.Decode(r.Raw)
		if err != nil {
			t.Fatal(err)
		}
		if control.Installing(d) != want[i] {
			t.Fatalf("record %d (%s): Installing = %v, want %v", i+1, d.Action, !want[i], want[i])
		}
	}
}
