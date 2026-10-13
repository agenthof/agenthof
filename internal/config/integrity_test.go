package config

import (
	"strings"
	"testing"
)

// TestIntegrityValidateFloorAccepted: the floor in every Go spelling — zero,
// explicit local/none, an empty-but-non-nil duplicate list — validates.
func TestIntegrityValidateFloorAccepted(t *testing.T) {
	for name, in := range map[string]Integrity{
		"zero":                 {},
		"sink local":           {Sink: "local"},
		"anchor none":          {Anchor: "none"},
		"both":                 {Sink: "local", Anchor: "none"},
		"empty duplicate list": {Sink: "local", Anchor: "none", Duplicate: []IntegrityBackend{}},
	} {
		if err := in.Validate(); err != nil {
			t.Errorf("%s: Validate = %v, want nil", name, err)
		}
	}
}

// TestIntegrityValidateRejectsByName pins every Validate fault verbatim, in
// the fixed order of the design (sink → anchor → duplicate → sink_backend →
// anchor_backend), matched exactly: no case-folding, no trimming.
func TestIntegrityValidateRejectsByName(t *testing.T) {
	const (
		sinkWorm      = `sink "worm" is reserved and not yet supported in this build (only local is implemented)`
		sinkExternal  = `sink "external" is reserved and not yet supported in this build (only local is implemented)`
		sinkDuplicate = `sink "duplicate" is reserved and not yet supported in this build; when it is, it is written as the duplicate: list, not as the sink value`
		anchorTlog    = `anchor "tlog" is reserved and not yet supported in this build (only none is implemented)`
		anchorSigned  = `anchor "signed" is reserved and not yet supported in this build (only none is implemented)`
		dupOne        = `duplicate names 1 sink(s); duplicate sinks are reserved and not yet supported in this build`
		dupTwo        = `duplicate names 2 sink(s); duplicate sinks are reserved and not yet supported in this build`
		sinkBackend   = `sink_backend is set but sink is local; backend coordinates are reserved for worm and external`
		anchorBackend = `anchor_backend is set but anchor is none; backend coordinates are reserved for tlog and signed`
	)
	cases := []struct {
		name string
		in   Integrity
		want string
	}{
		{"sink worm", Integrity{Sink: "worm"}, sinkWorm},
		{"sink external", Integrity{Sink: "external"}, sinkExternal},
		{"sink duplicate is early, not wrong", Integrity{Sink: "duplicate"}, sinkDuplicate},
		{"sink Local is not the floor", Integrity{Sink: "Local"}, `sink "Local" is not an integrity sink (want local; worm, external and duplicate are reserved)`},
		{"sink with a space is not the floor", Integrity{Sink: " local"}, `sink " local" is not an integrity sink (want local; worm, external and duplicate are reserved)`},
		{"sink s3", Integrity{Sink: "s3"}, `sink "s3" is not an integrity sink (want local; worm, external and duplicate are reserved)`},
		{"anchor tlog", Integrity{Anchor: "tlog"}, anchorTlog},
		{"anchor signed", Integrity{Anchor: "signed"}, anchorSigned},
		{"anchor TLOG", Integrity{Anchor: "TLOG"}, `anchor "TLOG" is not an integrity anchor (want none; tlog and signed are reserved)`},
		{"one duplicate entry, even empty", Integrity{Duplicate: []IntegrityBackend{{}}}, dupOne},
		{"two duplicate entries", Integrity{Duplicate: []IntegrityBackend{{Kind: "local"}, {Kind: "s3-object-lock"}}}, dupTwo},
		{"sink_backend kind at the floor", Integrity{SinkBackend: IntegrityBackend{Kind: "s3-object-lock"}}, sinkBackend},
		{"anchor_backend url at the floor", Integrity{AnchorBackend: IntegrityBackend{URL: "https://tsa.example/tsr"}}, anchorBackend},
		{"anchor_backend reached through its credential", Integrity{AnchorBackend: IntegrityBackend{Credential: BackendCredential{TokenEnv: "TSA_TOKEN"}}}, anchorBackend},
		// Order: the FIRST fault in the fixed order, never a later one.
		{"sink before anchor", Integrity{Sink: "worm", Anchor: "tlog"}, sinkWorm},
		{"anchor before duplicate", Integrity{Anchor: "tlog", Duplicate: []IntegrityBackend{{}}}, anchorTlog},
		{"duplicate before sink_backend", Integrity{Duplicate: []IntegrityBackend{{}}, SinkBackend: IntegrityBackend{Kind: "x"}}, dupOne},
		{"sink_backend before anchor_backend", Integrity{SinkBackend: IntegrityBackend{Kind: "x"}, AnchorBackend: IntegrityBackend{Kind: "y"}}, sinkBackend},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.in.Validate()
			if err == nil {
				t.Fatalf("Validate(%+v) = nil, want %q", c.in, c.want)
			}
			if err.Error() != c.want {
				t.Fatalf("Validate(%+v)\n got %q\nwant %q", c.in, err, c.want)
			}
			// Errors name keys and enum values, never a coordinate.
			for _, coord := range []string{"TSA_TOKEN", "https://tsa.example", "s3-object-lock"} {
				if strings.Contains(err.Error(), coord) {
					t.Fatalf("error must not echo a coordinate %q: %q", coord, err)
				}
			}
		})
	}
}

// TestIntegrityBackendIsSet: any field, including one nested in the
// credential, declares the backend — a half-filled block is never ignored.
func TestIntegrityBackendIsSet(t *testing.T) {
	if (IntegrityBackend{}).IsSet() {
		t.Fatal("zero backend must not be set")
	}
	for name, b := range map[string]IntegrityBackend{
		"kind":       {Kind: "rfc3161"},
		"url":        {URL: "https://tsa.example/tsr"},
		"credential": {Credential: BackendCredential{ClientSecretEnv: "TSA_CLIENT_SECRET"}},
	} {
		if !b.IsSet() {
			t.Errorf("%s: IsSet = false, want true", name)
		}
	}
}
