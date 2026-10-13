package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
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
// the fixed order Validate applies (sink → anchor → duplicate → sink_backend →
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

// assertFloor is the one definition of "the floor came back": every knob
// empty, no duplicate entries (yaml decodes `duplicate: []` to an empty
// non-nil slice, so compare the length, never the slice), no backend set.
func assertFloor(t *testing.T, in Integrity, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if in.Sink != "" && in.Sink != "local" || in.Anchor != "" && in.Anchor != "none" ||
		len(in.Duplicate) != 0 || in.SinkBackend.IsSet() || in.AnchorBackend.IsSet() {
		t.Fatalf("not the floor: %+v", in)
	}
	if err := in.Validate(); err != nil {
		t.Fatalf("the floor must validate: %v", err)
	}
}

// TestParseIntegrityFloorInEverySpelling: nil, empty, comment-only, {}, ~, a
// bare ---, a leading ---, a trailing ..., explicit local/none, and every
// absent/null/empty spelling of the reserved keys are the floor.
func TestParseIntegrityFloorInEverySpelling(t *testing.T) {
	for name, src := range map[string][]byte{
		"nil":                 nil,
		"empty":               []byte(""),
		"comment only":        []byte("# only a comment\n"),
		"empty mapping":       []byte("{}\n"),
		"tilde":               []byte("~\n"),
		"bare document mark":  []byte("---\n"),
		"leading mark":        []byte("---\nsink: local\n"),
		"trailing end mark":   []byte("sink: local\n...\n"),
		"sink local":          []byte("sink: local\n"),
		"anchor none":         []byte("anchor: none\n"),
		"both":                []byte("sink: local\nanchor: none\n"),
		"sink null":           []byte("sink: ~\n"),
		"duplicate empty":     []byte("duplicate: []\n"),
		"duplicate null":      []byte("duplicate: null\n"),
		"duplicate bare key":  []byte("duplicate:\n"),
		"sink_backend empty":  []byte("sink_backend: {}\n"),
		"sink_backend null":   []byte("sink_backend: ~\n"),
		"anchor_backend bare": []byte("anchor_backend:\n"),
		"trailing comment":    []byte("sink: local\n# trailing\n"),
	} {
		t.Run(name, func(t *testing.T) {
			in, err := ParseIntegrity(src)
			assertFloor(t, in, err)
		})
	}
}

// TestParseIntegrityRejectsMoreThanOneDocument: the one-document rule, applied
// before any document's content. yaml.Unmarshal would
// read the first document and drop the rest — `sink: local` followed by
// `anchor: tlog` would be the floor. The decoder refuses a second document of
// any kind, including the null document a trailing bare --- produces, before
// either document's content is looked at: an unknown key in the first
// document is never reported, and the first document is never returned.
func TestParseIntegrityRejectsMoreThanOneDocument(t *testing.T) {
	const want = "more than one YAML document; integrity.yaml holds exactly one"
	for name, in := range map[string]string{
		"two mappings":           "sink: local\n---\nanchor: tlog\n",
		"trailing bare mark":     "sink: local\n---\n",
		"two bare marks":         "---\n---\n",
		"fault in the first doc": "ancher: x\n---\nanchor: tlog\n",
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ParseIntegrity([]byte(in))
			if err == nil || err.Error() != want {
				t.Fatalf("err = %v, want %q", err, want)
			}
			if got.Sink != "" || got.Anchor != "" {
				t.Fatalf("the first document must not be returned: %+v", got)
			}
		})
	}
}

// TestParseIntegrityRejectsReservedValuesThroughYAML: the Validate rules
// reached from bytes, with the fixed order holding across the decode.
func TestParseIntegrityRejectsReservedValuesThroughYAML(t *testing.T) {
	for name, c := range map[string]struct{ in, want string }{
		"worm":                               {"sink: worm\n", `sink "worm" is reserved and not yet supported in this build (only local is implemented)`},
		"external":                           {"sink: external\n", `sink "external" is reserved and not yet supported in this build (only local is implemented)`},
		"sink duplicate":                     {"sink: duplicate\n", `sink "duplicate" is reserved and not yet supported in this build; when it is, it is written as the duplicate: list, not as the sink value`},
		"tlog":                               {"anchor: tlog\n", `anchor "tlog" is reserved and not yet supported in this build (only none is implemented)`},
		"signed":                             {"anchor: signed\n", `anchor "signed" is reserved and not yet supported in this build (only none is implemented)`},
		"Local":                              {"sink: Local\n", `sink "Local" is not an integrity sink (want local; worm, external and duplicate are reserved)`},
		"TLOG":                               {"anchor: TLOG\n", `anchor "TLOG" is not an integrity anchor (want none; tlog and signed are reserved)`},
		"s3":                                 {"sink: s3\n", `sink "s3" is not an integrity sink (want local; worm, external and duplicate are reserved)`},
		"one duplicate":                      {"duplicate:\n  - kind: local\n    url: file:///mnt/copy\n", `duplicate names 1 sink(s); duplicate sinks are reserved and not yet supported in this build`},
		"empty entry":                        {"duplicate: [{}]\n", `duplicate names 1 sink(s); duplicate sinks are reserved and not yet supported in this build`},
		"sink_backend":                       {"sink: local\nsink_backend:\n  kind: s3-object-lock\n", `sink_backend is set but sink is local; backend coordinates are reserved for worm and external`},
		"anchor_backend":                     {"anchor: none\nanchor_backend:\n  url: https://tsa.example/tsr\n", `anchor_backend is set but anchor is none; backend coordinates are reserved for tlog and signed`},
		"nested only":                        {"anchor_backend:\n  credential:\n    token_env: TSA_TOKEN\n", `anchor_backend is set but anchor is none; backend coordinates are reserved for tlog and signed`},
		"sink before anchor":                 {"sink: worm\nanchor: tlog\n", `sink "worm" is reserved and not yet supported in this build (only local is implemented)`},
		"duplicate before backend":           {"duplicate: [{}]\nsink_backend: {kind: x}\n", `duplicate names 1 sink(s); duplicate sinks are reserved and not yet supported in this build`},
		"sink_backend before anchor_backend": {"sink_backend: {kind: x}\nanchor_backend: {kind: y}\n", `sink_backend is set but sink is local; backend coordinates are reserved for worm and external`},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseIntegrity([]byte(c.in))
			if err == nil || err.Error() != c.want {
				t.Fatalf("%q\n got %v\nwant %q", c.in, err, c.want)
			}
		})
	}
}

// TestParseIntegrityRejectsNonMappingsAndUnknownKeys: the shape rules at every
// level — the node is a mapping (a list for duplicate), each key is a plain
// scalar, and each key is known — reported with its position and line and
// never a Go type name. A typo can never floor, an alias- or complex-keyed
// entry can never floor, and a value-looking key is refused as a key.
func TestParseIntegrityRejectsNonMappingsAndUnknownKeys(t *testing.T) {
	const (
		top  = "sink, anchor, duplicate, sink_backend, anchor_backend"
		be   = "kind, url, credential"
		cred = "credential_source, token_env, grant_type, client_auth, issuer, token_endpoint, client_id_env, client_secret_env, scope, audience"
	)
	for name, c := range map[string]struct{ in, want string }{
		"scalar document":          {"local\n", "line 1: integrity.yaml must be a mapping (allowed keys: " + top + ")"},
		"sequence document":        {"- a\n", "line 1: integrity.yaml must be a mapping (allowed keys: " + top + ")"},
		"unknown top key":          {"ancher: tlog\n", `line 1: unknown key "ancher" (allowed keys: ` + top + ")"},
		"unknown before reserved":  {"ancher: x\nsink: worm\n", `line 1: unknown key "ancher" (allowed keys: ` + top + ")"},
		"unknown on a later line":  {"sink: local\nancher: tlog\n", `line 2: unknown key "ancher" (allowed keys: ` + top + ")"},
		"sink_backend unknown key": {"sink_backend: {kinds: x}\n", `line 1: unknown key "kinds" in sink_backend (allowed keys: ` + be + ")"},
		"sink_backend scalar":      {"sink_backend: s3\n", "line 1: sink_backend must be a mapping (allowed keys: " + be + ")"},
		"duplicate scalar entry":   {"duplicate: [s3]\n", "line 1: duplicate[0] must be a mapping (allowed keys: " + be + ")"},
		"duplicate null entry":     {"duplicate: [~]\n", "line 1: duplicate[0] must be a mapping (allowed keys: " + be + ")"},
		"duplicate second entry":   {"duplicate:\n  - {}\n  - s3\n", "line 3: duplicate[1] must be a mapping (allowed keys: " + be + ")"},
		"duplicate not a list":     {"duplicate: s3\n", "line 1: duplicate must be a list of backends (each a mapping; allowed keys: " + be + ")"},
		"duplicate a mapping":      {"duplicate: {kind: x}\n", "line 1: duplicate must be a list of backends (each a mapping; allowed keys: " + be + ")"},
		"credential value key":     {"anchor_backend:\n  credential:\n    token: VALUE\n", `line 3: unknown key "token" in anchor_backend.credential (allowed keys: ` + cred + ")"},
		"credential scalar":        {"anchor_backend:\n  credential: x\n", "line 2: anchor_backend.credential must be a mapping (allowed keys: " + cred + ")"},
		"credential in duplicate":  {"duplicate:\n  - kind: local\n    credential: [a]\n", "line 3: duplicate[0].credential must be a mapping (allowed keys: " + cred + ")"},
		"top alias key":            {"sink: &anchor local\n*anchor : tlog\n", "line 2: key must be a plain scalar (allowed keys: " + top + ")"},
		"top complex key":          {"? [a]\n: b\n", "line 1: key must be a plain scalar (allowed keys: " + top + ")"},
		"backend complex key":      {"sink_backend:\n  ? [a]\n  : b\n", "line 2: key must be a plain scalar in sink_backend (allowed keys: " + be + ")"},
		"credential complex key":   {"anchor_backend:\n  credential:\n    ? [a]\n    : b\n", "line 3: key must be a plain scalar in anchor_backend.credential (allowed keys: " + cred + ")"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseIntegrity([]byte(c.in))
			if err == nil || err.Error() != c.want {
				t.Fatalf("%q\n got %v\nwant %q", c.in, err, c.want)
			}
			for _, leak := range []string{"rawIntegrity", "config.", "VALUE"} {
				if strings.Contains(err.Error(), leak) {
					t.Fatalf("error must not contain %q: %q", leak, err)
				}
			}
		})
	}
}

// TestParseIntegrityMalformedIsNeverTheFloor: a syntax fault, a duplicate
// key (yaml.v3's own refusal), and a wrong scalar type are errors, never a
// zero posture with err nil.
func TestParseIntegrityMalformedIsNeverTheFloor(t *testing.T) {
	for name, c := range map[string]struct{ in, fault string }{
		"syntax":        {"sink: [\n", "line 1"},
		"duplicate key": {"sink: local\nsink: worm\n", "already defined"},
		"list for sink": {"sink: [a]\n", "cannot unmarshal"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseIntegrity([]byte(c.in))
			if err == nil {
				t.Fatalf("%q parsed as the floor; want a refusal", c.in)
			}
			if !strings.Contains(err.Error(), c.fault) {
				t.Fatalf("%q: error %q must name the fault %q", c.in, err, c.fault)
			}
			if strings.Contains(err.Error(), "config.") {
				t.Fatalf("error must not leak a Go type name: %q", err)
			}
		})
	}
}

// TestParseIntegrityBrokerRefCarriesNames: the credential shape decodes
// env-var NAMES (there is no field a value could land in), the file as a
// whole is refused at the floor, and the refusal echoes none of them.
func TestParseIntegrityBrokerRefCarriesNames(t *testing.T) {
	src := []byte("anchor: none\nanchor_backend:\n  kind: rfc3161\n  url: https://tsa.example/tsr\n  credential:\n" +
		"    credential_source: static_env\n    grant_type: client_credentials\n    client_auth: client_secret_basic\n" +
		"    token_env: TSA_TOKEN\n    client_id_env: TSA_CLIENT_ID\n    client_secret_env: TSA_CLIENT_SECRET\n")
	var in Integrity
	if err := yaml.Unmarshal(src, &in); err != nil { // the shape alone, before Validate
		t.Fatal(err)
	}
	c := in.AnchorBackend.Credential
	if in.AnchorBackend.Kind != "rfc3161" || in.AnchorBackend.URL != "https://tsa.example/tsr" ||
		c.CredentialSource != "static_env" || c.GrantType != "client_credentials" || c.ClientAuth != "client_secret_basic" ||
		c.TokenEnv != "TSA_TOKEN" || c.ClientIDEnv != "TSA_CLIENT_ID" || c.ClientSecretEnv != "TSA_CLIENT_SECRET" {
		t.Fatalf("decoded %+v", in.AnchorBackend)
	}
	_, err := ParseIntegrity(src)
	if err == nil || err.Error() != "anchor_backend is set but anchor is none; backend coordinates are reserved for tlog and signed" {
		t.Fatalf("err = %v", err)
	}
	for _, coord := range []string{"TSA_TOKEN", "TSA_CLIENT_ID", "TSA_CLIENT_SECRET", "tsa.example", "rfc3161"} {
		if strings.Contains(err.Error(), coord) {
			t.Fatalf("the refusal must not echo %q: %q", coord, err)
		}
	}
}

// TestParseIntegrityRoundTrip: a floor Integrity marshalled by yaml.v3 parses
// back as the floor — the zero value and the explicit spelling both.
func TestParseIntegrityRoundTrip(t *testing.T) {
	for name, in := range map[string]Integrity{"zero": {}, "explicit": {Sink: "local", Anchor: "none"}} {
		t.Run(name, func(t *testing.T) {
			b, err := yaml.Marshal(in)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ParseIntegrity(b)
			assertFloor(t, got, err)
			if got.Sink != in.Sink || got.Anchor != in.Anchor {
				t.Fatalf("round trip %+v → %+v", in, got)
			}
		})
	}
}
