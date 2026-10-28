package config

import (
	"reflect"
	"strings"
	"testing"
	"time"

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
		sinkWormUnset = `sink is worm but sink_backend is not set; name the write-once store (kind s3-object-lock, url, mode compliance, retention)`
		sinkExternal  = `sink "external" is reserved and not yet supported in this build (only local and worm are implemented)`
		sinkDuplicate = `sink "duplicate" is reserved and not yet supported in this build; when it is, it is written as the duplicate: list, not as the sink value`
		anchorSigned  = `anchor "signed" is reserved and not yet supported in this build (only none and tlog are implemented)`
		dupOne        = `duplicate names 1 sink(s); duplicate sinks are reserved and not yet supported in this build`
		dupTwo        = `duplicate names 2 sink(s); duplicate sinks are reserved and not yet supported in this build`
		sinkBackend   = `sink_backend is set but sink is local; backend coordinates belong to worm (and to external, which is reserved)`
		anchorBackend = `anchor_backend is set but anchor is none; backend coordinates are reserved for tlog and signed`
	)
	cases := []struct {
		name string
		in   Integrity
		want string
	}{
		{"sink worm, no backend", Integrity{Sink: "worm"}, sinkWormUnset},
		{"sink external", Integrity{Sink: "external"}, sinkExternal},
		{"sink duplicate is early, not wrong", Integrity{Sink: "duplicate"}, sinkDuplicate},
		{"sink Local is not the floor", Integrity{Sink: "Local"}, `sink "Local" is not an integrity sink (want local or worm; external and duplicate are reserved)`},
		{"sink with a space is not the floor", Integrity{Sink: " local"}, `sink " local" is not an integrity sink (want local or worm; external and duplicate are reserved)`},
		{"sink s3", Integrity{Sink: "s3"}, `sink "s3" is not an integrity sink (want local or worm; external and duplicate are reserved)`},
		{"anchor signed", Integrity{Anchor: "signed"}, anchorSigned},
		{"anchor TLOG", Integrity{Anchor: "TLOG"}, `anchor "TLOG" is not an integrity anchor (want none or tlog; signed is reserved)`},
		{"one duplicate entry, even empty", Integrity{Duplicate: []IntegrityBackend{{}}}, dupOne},
		{"two duplicate entries", Integrity{Duplicate: []IntegrityBackend{{Kind: "local"}, {Kind: "s3-object-lock"}}}, dupTwo},
		{"sink_backend kind at the floor", Integrity{SinkBackend: IntegrityBackend{Kind: "s3-object-lock"}}, sinkBackend},
		{"anchor_backend url at the floor", Integrity{AnchorBackend: IntegrityBackend{URL: "https://tsa.example/tsr"}}, anchorBackend},
		{"anchor_backend reached through its credential", Integrity{AnchorBackend: IntegrityBackend{Credential: BackendCredential{TokenEnv: "TSA_TOKEN"}}}, anchorBackend},
		// Order: the FIRST fault in the fixed order, never a later one.
		{"sink before anchor", Integrity{Sink: "worm", Anchor: "tlog"}, sinkWormUnset},
		{"anchor before duplicate", Integrity{Anchor: "signed", Duplicate: []IntegrityBackend{{}}}, anchorSigned},
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
			for _, coord := range []string{"TSA_TOKEN", "https://tsa.example"} {
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
		"worm":                               {"sink: worm\n", `sink is worm but sink_backend is not set; name the write-once store (kind s3-object-lock, url, mode compliance, retention)`},
		"external":                           {"sink: external\n", `sink "external" is reserved and not yet supported in this build (only local and worm are implemented)`},
		"sink duplicate":                     {"sink: duplicate\n", `sink "duplicate" is reserved and not yet supported in this build; when it is, it is written as the duplicate: list, not as the sink value`},
		"tlog":                               {"anchor: tlog\n", `anchor is tlog but anchor_backend is not set; name the transparency log (kind transparency-log, url)`},
		"signed":                             {"anchor: signed\n", `anchor "signed" is reserved and not yet supported in this build (only none and tlog are implemented)`},
		"Local":                              {"sink: Local\n", `sink "Local" is not an integrity sink (want local or worm; external and duplicate are reserved)`},
		"TLOG":                               {"anchor: TLOG\n", `anchor "TLOG" is not an integrity anchor (want none or tlog; signed is reserved)`},
		"s3":                                 {"sink: s3\n", `sink "s3" is not an integrity sink (want local or worm; external and duplicate are reserved)`},
		"one duplicate":                      {"duplicate:\n  - kind: local\n    url: file:///mnt/copy\n", `duplicate names 1 sink(s); duplicate sinks are reserved and not yet supported in this build`},
		"empty entry":                        {"duplicate: [{}]\n", `duplicate names 1 sink(s); duplicate sinks are reserved and not yet supported in this build`},
		"sink_backend":                       {"sink: local\nsink_backend:\n  kind: s3-object-lock\n", `sink_backend is set but sink is local; backend coordinates belong to worm (and to external, which is reserved)`},
		"anchor_backend":                     {"anchor: none\nanchor_backend:\n  url: https://tsa.example/tsr\n", `anchor_backend is set but anchor is none; backend coordinates are reserved for tlog and signed`},
		"nested only":                        {"anchor_backend:\n  credential:\n    token_env: TSA_TOKEN\n", `anchor_backend is set but anchor is none; backend coordinates are reserved for tlog and signed`},
		"sink before anchor":                 {"sink: worm\nanchor: tlog\n", `sink is worm but sink_backend is not set; name the write-once store (kind s3-object-lock, url, mode compliance, retention)`},
		"duplicate before backend":           {"duplicate: [{}]\nsink_backend: {kind: x}\n", `duplicate names 1 sink(s); duplicate sinks are reserved and not yet supported in this build`},
		"sink_backend before anchor_backend": {"sink_backend: {kind: x}\nanchor_backend: {kind: y}\n", `sink_backend is set but sink is local; backend coordinates belong to worm (and to external, which is reserved)`},
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
		top  = "sink, anchor, anchor_runs, duplicate, sink_backend, anchor_backend"
		be   = "kind, url, region, mode, retention, credential"
		cred = "credential_source, token_env, grant_type, client_auth, issuer, token_endpoint, client_id_env, client_secret_env, scope, audience"
	)
	for name, c := range map[string]struct{ in, want string }{
		"scalar document":          {"local\n", "line 1: integrity.yaml must be a mapping (allowed keys: " + top + ")"},
		"sequence document":        {"- a\n", "line 1: integrity.yaml must be a mapping (allowed keys: " + top + ")"},
		"unknown top key":          {"ancher: tlog\n", `line 1: unknown key "ancher" (allowed keys: ` + top + ")"},
		"unknown before reserved":  {"ancher: x\nsink: worm\n", `line 1: unknown key "ancher" (allowed keys: ` + top + ")"},
		"unknown on a later line":  {"sink: local\nancher: tlog\n", `line 2: unknown key "ancher" (allowed keys: ` + top + ")"},
		"sink_backend unknown key": {"sink_backend: {kinds: x}\n", `line 1: unknown key "kinds" in sink_backend (allowed keys: ` + be + ")"},
		"sink_backend addressing":  {"sink: worm\nsink_backend:\n  addressing: virtual\n", "line 3: unknown key \"addressing\" in sink_backend (allowed keys: " + be + ")"},
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

// TestIntegrityValidateTlog pins the anchor: tlog coordinate checks with their
// exact strings and their order (first fault only), and the accepted shapes:
// kind empty or
// transparency-log; a direct-bearer credential; client_credentials with no
// env names (shape-only — the broker fails at use, recorded).
func TestIntegrityValidateTlog(t *testing.T) {
	tlog := func(b IntegrityBackend) Integrity { return Integrity{Anchor: "tlog", AnchorBackend: b} }
	url := "https://rekor.sigstore.dev"
	for name, in := range map[string]Integrity{
		"kind empty":                  tlog(IntegrityBackend{URL: url}),
		"kind transparency-log":       tlog(IntegrityBackend{Kind: "transparency-log", URL: url}),
		"http in-cluster":             tlog(IntegrityBackend{URL: "http://rekor.internal:3000"}),
		"path prefix":                 tlog(IntegrityBackend{URL: "https://logs.example/rekor"}),
		"direct bearer":               tlog(IntegrityBackend{URL: url, Credential: BackendCredential{TokenEnv: "REKOR_TOKEN"}}),
		"static_env spelled":          tlog(IntegrityBackend{URL: url, Credential: BackendCredential{CredentialSource: "static_env", TokenEnv: "REKOR_TOKEN"}}),
		"client_credentials, no envs": tlog(IntegrityBackend{URL: url, Credential: BackendCredential{GrantType: "client_credentials"}}),
	} {
		if err := in.Validate(); err != nil {
			t.Errorf("%s: Validate = %v, want nil", name, err)
		}
	}
	cases := []struct {
		name string
		in   Integrity
		want string
	}{
		{"3a signed", Integrity{Anchor: "signed"}, `anchor "signed" is reserved and not yet supported in this build (only none and tlog are implemented)`},
		{"3a signed with coordinates", Integrity{Anchor: "signed", AnchorBackend: IntegrityBackend{URL: url}}, `anchor "signed" is reserved and not yet supported in this build (only none and tlog are implemented)`},
		{"3b no backend", Integrity{Anchor: "tlog"}, `anchor is tlog but anchor_backend is not set; name the transparency log (kind transparency-log, url)`},
		{"3c rfc3161", tlog(IntegrityBackend{Kind: "rfc3161", URL: "https://tsa.example/tsr"}), `anchor_backend kind "rfc3161" is reserved and not yet supported in this build (only transparency-log is implemented)`},
		{"3d other kind", tlog(IntegrityBackend{Kind: "kms", URL: url}), `anchor_backend kind "kms" is not an anchor backend kind (want transparency-log; rfc3161 is reserved)`},
		{"3d case", tlog(IntegrityBackend{Kind: "Transparency-Log", URL: url}), `anchor_backend kind "Transparency-Log" is not an anchor backend kind (want transparency-log; rfc3161 is reserved)`},
		{"3e url empty", tlog(IntegrityBackend{Kind: "transparency-log"}), `anchor_backend.url is required for anchor: tlog (the Sigstore public-good log is https://rekor.sigstore.dev)`},
		{"3e credential only", tlog(IntegrityBackend{Credential: BackendCredential{TokenEnv: "X"}}), `anchor_backend.url is required for anchor: tlog (the Sigstore public-good log is https://rekor.sigstore.dev)`},
		{"3f relative", tlog(IntegrityBackend{URL: "rekor.sigstore.dev"}), `anchor_backend.url "rekor.sigstore.dev" is not an absolute http(s) URL without credentials`},
		{"3f ftp", tlog(IntegrityBackend{URL: "ftp://rekor.sigstore.dev"}), `anchor_backend.url "ftp://rekor.sigstore.dev" is not an absolute http(s) URL without credentials`},
		{"3f userinfo", tlog(IntegrityBackend{URL: "https://u:p@rekor.sigstore.dev"}), `anchor_backend.url "https://u:p@rekor.sigstore.dev" is not an absolute http(s) URL without credentials`},
		{"3f query", tlog(IntegrityBackend{URL: url + "/?treeID=1"}), `anchor_backend.url "https://rekor.sigstore.dev/?treeID=1" is not an absolute http(s) URL without credentials`},
		{"3f fragment", tlog(IntegrityBackend{URL: url + "#x"}), `anchor_backend.url "https://rekor.sigstore.dev#x" is not an absolute http(s) URL without credentials`},
		{"3g token_exchange", tlog(IntegrityBackend{URL: url, Credential: BackendCredential{GrantType: "token_exchange"}}), `anchor_backend.credential: grant_type "token_exchange" is not supported for an anchor backend (want client_credentials, or a direct bearer via token_env)`},
		{"3g source", tlog(IntegrityBackend{URL: url, Credential: BackendCredential{CredentialSource: "vault", TokenEnv: "X"}}), `anchor_backend.credential: credential_source "vault" is not supported for an anchor backend (want static_env)`},
		{"3g grant before source", tlog(IntegrityBackend{URL: url, Credential: BackendCredential{CredentialSource: "vault", GrantType: "token_exchange"}}), `anchor_backend.credential: grant_type "token_exchange" is not supported for an anchor backend (want client_credentials, or a direct bearer via token_env)`},
		{"3c before 3e", tlog(IntegrityBackend{Kind: "rfc3161"}), `anchor_backend kind "rfc3161" is reserved and not yet supported in this build (only transparency-log is implemented)`},
		{"3e before 3g", tlog(IntegrityBackend{Credential: BackendCredential{GrantType: "token_exchange"}}), `anchor_backend.url is required for anchor: tlog (the Sigstore public-good log is https://rekor.sigstore.dev)`},
		{"anchor_backend set while anchor none", Integrity{Anchor: "none", AnchorBackend: IntegrityBackend{URL: url}}, `anchor_backend is set but anchor is none; backend coordinates are reserved for tlog and signed`},
		{"sink still first", Integrity{Sink: "worm", Anchor: "tlog", AnchorBackend: IntegrityBackend{URL: url}}, `sink is worm but sink_backend is not set; name the write-once store (kind s3-object-lock, url, mode compliance, retention)`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.in.Validate()
			if err == nil || err.Error() != c.want {
				t.Fatalf("Validate(%+v)\n got %v\nwant %q", c.in, err, c.want)
			}
			if strings.Contains(err.Error(), "REKOR_TOKEN") || strings.Contains(err.Error(), "tsa.example") {
				t.Fatalf("error must not echo a credential name or a reserved coordinate: %q", err)
			}
		})
	}
}

// TestParseIntegrityTlogDefaultsKind: a file naming only the url parses with
// Kind "transparency-log" — the one default, harmless because url is still
// required; a spelled kind is kept; a floor file still has an empty kind.
func TestParseIntegrityTlogDefaultsKind(t *testing.T) {
	in, err := ParseIntegrity([]byte("anchor: tlog\nanchor_backend:\n  url: https://rekor.sigstore.dev\n"))
	if err != nil || in.Anchor != "tlog" || in.AnchorBackend.Kind != "transparency-log" || in.AnchorBackend.URL != "https://rekor.sigstore.dev" {
		t.Fatalf("%+v %v", in, err)
	}
	in, err = ParseIntegrity([]byte("anchor: tlog\nanchor_backend: {kind: transparency-log, url: http://rekor.internal:3000}\n"))
	if err != nil || in.AnchorBackend.Kind != "transparency-log" {
		t.Fatalf("%+v %v", in, err)
	}
	if in, err := ParseIntegrity([]byte("sink: local\nanchor: none\n")); err != nil || in.AnchorBackend.Kind != "" {
		t.Fatalf("floor must not gain a kind: %+v %v", in, err)
	}
}

// wormBackend is the spec's complete s3-object-lock example, the base every
// validateSinkBackend row mutates.
func wormBackend(mut func(*IntegrityBackend)) Integrity {
	b := IntegrityBackend{
		Kind:      "s3-object-lock",
		URL:       "https://s3.eu-central-1.amazonaws.com/acme-ledger-worm/agenthof",
		Region:    "eu-central-1",
		Mode:      "compliance",
		Retention: "7y",
		Credential: BackendCredential{
			CredentialSource: "static_env",
			ClientAuth:       "sigv4",
			ClientIDEnv:      "AGENTHOF_WORM_ACCESS_KEY_ID",
			ClientSecretEnv:  "AGENTHOF_WORM_SECRET_ACCESS_KEY",
			TokenEnv:         "AGENTHOF_WORM_SESSION_TOKEN",
		},
	}
	if mut != nil {
		mut(&b)
	}
	return Integrity{Sink: "worm", SinkBackend: b}
}

// TestValidateSinkBackendTable pins every sink: worm rule verbatim, in the
// fixed order, first fault only; the complete posture validates.
func TestValidateSinkBackendTable(t *testing.T) {
	const (
		ok          = "https://s3.example/bucket"
		credPrefix  = "sink_backend.credential: "
		minimalCred = "static_env"
	)
	good := BackendCredential{CredentialSource: minimalCred, ClientAuth: "sigv4", ClientIDEnv: "AK", ClientSecretEnv: "SK"}
	min := func(mut func(*IntegrityBackend)) Integrity { // a backend with only what each row needs
		b := IntegrityBackend{Kind: "s3-object-lock", URL: ok, Mode: "compliance", Retention: "7y", Credential: good}
		if mut != nil {
			mut(&b)
		}
		return Integrity{Sink: "worm", SinkBackend: b}
	}
	cases := []struct {
		name string
		in   Integrity
		want string
	}{
		{"not set", Integrity{Sink: "worm"}, sinkWormUnsetText},
		{"azure reserved", min(func(b *IntegrityBackend) { b.Kind = "azure-immutable-blob" }), `sink_backend kind "azure-immutable-blob" is reserved and not yet supported in this build (only s3-object-lock is implemented)`},
		{"gcs reserved", Integrity{Sink: "worm", SinkBackend: IntegrityBackend{Kind: "gcs-bucket-lock"}}, `sink_backend kind "gcs-bucket-lock" is reserved and not yet supported in this build (only s3-object-lock is implemented)`},
		{"empty kind", min(func(b *IntegrityBackend) { b.Kind = "" }), `sink_backend kind "" is not a write-once sink kind (want s3-object-lock; azure-immutable-blob and gcs-bucket-lock are reserved)`},
		{"other kind", min(func(b *IntegrityBackend) { b.Kind = "S3-Object-Lock" }), `sink_backend kind "S3-Object-Lock" is not a write-once sink kind (want s3-object-lock; azure-immutable-blob and gcs-bucket-lock are reserved)`},
		{"url empty", min(func(b *IntegrityBackend) { b.URL = "" }), `sink_backend.url is required for sink: worm (endpoint + /bucket[/prefix], e.g. https://s3.<region>.amazonaws.com/<bucket>)`},
		{"url userinfo", min(func(b *IntegrityBackend) { b.URL = "https://a:b@s3.example/bucket" }), `sink_backend.url "https://a:b@s3.example/bucket" is not an absolute http(s) URL without credentials`},
		{"url relative", min(func(b *IntegrityBackend) { b.URL = "s3.example/bucket" }), `sink_backend.url "s3.example/bucket" is not an absolute http(s) URL without credentials`},
		{"url query", min(func(b *IntegrityBackend) { b.URL = "https://s3.example/bucket?x=1" }), `sink_backend.url "https://s3.example/bucket?x=1" is not an absolute http(s) URL without credentials`},
		{"url no bucket", min(func(b *IntegrityBackend) { b.URL = "https://s3.example" }), `sink_backend.url "https://s3.example" names no bucket (want endpoint + /bucket[/prefix])`},
		{"url slash only", min(func(b *IntegrityBackend) { b.URL = "https://s3.example/" }), `sink_backend.url "https://s3.example/" names no bucket (want endpoint + /bucket[/prefix])`},
		{"mode empty", min(func(b *IntegrityBackend) { b.Mode = "" }), `sink_backend.mode is required for s3-object-lock and must be compliance (governance mode can be lifted by a privileged user and is refused)`},
		{"mode governance", min(func(b *IntegrityBackend) { b.Mode = "governance" }), `sink_backend.mode "governance" is refused: a governance-mode lock can be bypassed by a privileged user; use compliance`},
		{"mode other", min(func(b *IntegrityBackend) { b.Mode = "COMPLIANCE" }), `sink_backend.mode "COMPLIANCE" is not an object-lock mode (want compliance)`},
		{"retention empty", min(func(b *IntegrityBackend) { b.Retention = "" }), `sink_backend.retention is required for s3-object-lock: <n>d or <n>y (e.g. 7y)`},
		{"retention space", min(func(b *IntegrityBackend) { b.Retention = "7 y" }), `sink_backend.retention "7 y" is not a retention (want <n>d or <n>y)`},
		{"retention zero", min(func(b *IntegrityBackend) { b.Retention = "0d" }), `sink_backend.retention "0d" is not a retention (want <n>d or <n>y)`},
		{"retention over cap in years", min(func(b *IntegrityBackend) { b.Retention = "101y" }), `sink_backend.retention "101y" exceeds 100y`},
		{"retention over cap in days", min(func(b *IntegrityBackend) { b.Retention = "36501d" }), `sink_backend.retention "36501d" exceeds 100y`},
		{"retention overflow", min(func(b *IntegrityBackend) { b.Retention = "99999999999999999999d" }), `sink_backend.retention "99999999999999999999d" exceeds 100y`},
		{"region bad", min(func(b *IntegrityBackend) { b.Region = "EU-Central-1" }), `sink_backend.region "EU-Central-1" is not a region name`},
		{"cred source ambient", min(func(b *IntegrityBackend) { b.Credential.CredentialSource = "ambient" }), credPrefix + `credential_source "ambient" is not supported for a write-once sink (want static_env)`},
		{"cred source web_identity", min(func(b *IntegrityBackend) { b.Credential.CredentialSource = "web_identity" }), credPrefix + `credential_source "web_identity" is not supported for a write-once sink (want static_env)`},
		{"cred grant", min(func(b *IntegrityBackend) { b.Credential.GrantType = "client_credentials" }), credPrefix + `grant_type "client_credentials" is not supported for a write-once sink (a signing key pair is used directly; leave grant_type unset)`},
		{"cred auth empty", min(func(b *IntegrityBackend) { b.Credential.ClientAuth = "" }), credPrefix + `client_auth must be sigv4 for s3-object-lock`},
		{"cred auth other", min(func(b *IntegrityBackend) { b.Credential.ClientAuth = "client_secret_basic" }), credPrefix + `client_auth must be sigv4 for s3-object-lock`},
		{"cred id empty", min(func(b *IntegrityBackend) { b.Credential.ClientIDEnv = "" }), credPrefix + `client_id_env and client_secret_env are required (the access key id and secret access key env NAMES)`},
		{"cred secret empty", min(func(b *IntegrityBackend) { b.Credential.ClientSecretEnv = "" }), credPrefix + `client_id_env and client_secret_env are required (the access key id and secret access key env NAMES)`},
		{"cred issuer", min(func(b *IntegrityBackend) { b.Credential.Issuer = "https://idp.example" }), credPrefix + `issuer is not used by sigv4`},
		{"cred token_endpoint", min(func(b *IntegrityBackend) { b.Credential.TokenEndpoint = "https://idp.example/token" }), credPrefix + `token_endpoint is not used by sigv4`},
		{"cred scope", min(func(b *IntegrityBackend) { b.Credential.Scope = "s" }), credPrefix + `scope is not used by sigv4`},
		{"cred audience", min(func(b *IntegrityBackend) { b.Credential.Audience = "a" }), credPrefix + `audience is not used by sigv4`},
		{"anchor coordinate", Integrity{Sink: "worm", SinkBackend: min(nil).SinkBackend, Anchor: "tlog", AnchorBackend: IntegrityBackend{URL: "https://rekor.sigstore.dev", Retention: "7y"}}, `anchor_backend.retention is not a coordinate of an anchor backend`},
		{"anchor coordinate region", Integrity{Anchor: "tlog", AnchorBackend: IntegrityBackend{URL: "https://rekor.sigstore.dev", Region: "eu-central-1"}}, `anchor_backend.region is not a coordinate of an anchor backend`},
		{"anchor coordinate mode", Integrity{Anchor: "tlog", AnchorBackend: IntegrityBackend{URL: "https://rekor.sigstore.dev", Mode: "compliance"}}, `anchor_backend.mode is not a coordinate of an anchor backend`},
		{"anchor coordinate before its credential", Integrity{Anchor: "tlog", AnchorBackend: IntegrityBackend{URL: "https://rekor.sigstore.dev", Mode: "compliance", Credential: BackendCredential{GrantType: "token_exchange"}}}, `anchor_backend.mode is not a coordinate of an anchor backend`},
		{"sink fault before anchor fault", Integrity{Sink: "worm", Anchor: "tlog", AnchorBackend: IntegrityBackend{Kind: "rfc3161"}}, sinkWormUnsetText},
		{"external still reserved", Integrity{Sink: "external"}, `sink "external" is reserved and not yet supported in this build (only local and worm are implemented)`},
		{"sink_backend at the floor", Integrity{SinkBackend: IntegrityBackend{Kind: "s3-object-lock"}}, `sink_backend is set but sink is local; backend coordinates belong to worm (and to external, which is reserved)`},
		{"unknown sink", Integrity{Sink: "s3"}, `sink "s3" is not an integrity sink (want local or worm; external and duplicate are reserved)`},
		{"duplicate stays reserved under worm", func() Integrity { in := min(nil); in.Duplicate = []IntegrityBackend{{}}; return in }(), `duplicate names 1 sink(s); duplicate sinks are reserved and not yet supported in this build`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.in.Validate()
			if err == nil || err.Error() != c.want {
				t.Fatalf("Validate(%+v)\n got %v\nwant %q", c.in, err, c.want)
			}
		})
	}

	for name, in := range map[string]Integrity{
		"complete":                wormBackend(nil),
		"no region, no token_env": wormBackend(func(b *IntegrityBackend) { b.Region = ""; b.Credential.TokenEnv = "" }),
		"http MinIO with prefix":  min(func(b *IntegrityBackend) { b.URL = "http://minio.internal:9000/ledger/prefix" }),
		"100y":                    min(func(b *IntegrityBackend) { b.Retention = "100y" }),
		"36500d":                  min(func(b *IntegrityBackend) { b.Retention = "36500d" }),
		"1d":                      min(func(b *IntegrityBackend) { b.Retention = "1d" }),
		"static_env left empty":   min(func(b *IntegrityBackend) { b.Credential.CredentialSource = "" }),
		"layered with tlog": func() Integrity {
			in := wormBackend(nil)
			in.Anchor = "tlog"
			in.AnchorBackend = IntegrityBackend{URL: "https://rekor.sigstore.dev"}
			return in
		}(),
	} {
		if err := in.Validate(); err != nil {
			t.Errorf("%s: Validate = %v, want nil", name, err)
		}
	}
}

// sinkWormUnsetText is the row-1 text; named once for the table above.
const sinkWormUnsetText = `sink is worm but sink_backend is not set; name the write-once store (kind s3-object-lock, url, mode compliance, retention)`

// TestParseRetention: the one place <n>d|<n>y is read. y is 365 days; the
// minimum form (1d) is the minimum, the cap is 100y. The below-minimum text
// is unreachable by grammar — 0d fails the grammar first — and pinned so.
func TestParseRetention(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"1d":     RetentionDay,
		"30d":    30 * RetentionDay,
		"7y":     7 * RetentionYear,
		"1y":     365 * RetentionDay,
		"36500d": RetentionMax,
		"100y":   RetentionMax,
	} {
		got, err := ParseRetention(in)
		if err != nil || got != want {
			t.Errorf("ParseRetention(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if RetentionMin != RetentionDay || RetentionYear != 365*24*time.Hour || RetentionMax != 100*RetentionYear {
		t.Fatalf("bounds: min %v year %v max %v", RetentionMin, RetentionYear, RetentionMax)
	}
	for in, want := range map[string]string{
		"":                      `sink_backend.retention is required for s3-object-lock: <n>d or <n>y (e.g. 7y)`,
		"7":                     `sink_backend.retention "7" is not a retention (want <n>d or <n>y)`,
		"7 y":                   `sink_backend.retention "7 y" is not a retention (want <n>d or <n>y)`,
		" 7y":                   `sink_backend.retention " 7y" is not a retention (want <n>d or <n>y)`,
		"7Y":                    `sink_backend.retention "7Y" is not a retention (want <n>d or <n>y)`,
		"-1d":                   `sink_backend.retention "-1d" is not a retention (want <n>d or <n>y)`,
		"1.5y":                  `sink_backend.retention "1.5y" is not a retention (want <n>d or <n>y)`,
		"07y":                   `sink_backend.retention "07y" is not a retention (want <n>d or <n>y)`,
		"0d":                    `sink_backend.retention "0d" is not a retention (want <n>d or <n>y)`,
		"0y":                    `sink_backend.retention "0y" is not a retention (want <n>d or <n>y)`,
		"101y":                  `sink_backend.retention "101y" exceeds 100y`,
		"36501d":                `sink_backend.retention "36501d" exceeds 100y`,
		"99999999999999999999d": `sink_backend.retention "99999999999999999999d" exceeds 100y`,
		"9223372036854775807y":  `sink_backend.retention "9223372036854775807y" exceeds 100y`,
	} {
		if got, err := ParseRetention(in); err == nil || err.Error() != want || got != 0 {
			t.Errorf("ParseRetention(%q) = %v, %v; want error %q", in, got, err, want)
		}
	}
}

// TestParseIntegrityWormComplete: the spec's document decodes to exactly the
// expected struct — Region, Mode and Retention filled, nothing defaulted.
func TestParseIntegrityWormComplete(t *testing.T) {
	src := "sink: worm\nsink_backend:\n  kind: s3-object-lock\n" +
		"  url: https://s3.eu-central-1.amazonaws.com/acme-ledger-worm/agenthof\n" +
		"  region: eu-central-1\n  mode: compliance\n  retention: 7y\n  credential:\n" +
		"    credential_source: static_env\n    client_auth: sigv4\n" +
		"    client_id_env: AGENTHOF_WORM_ACCESS_KEY_ID\n    client_secret_env: AGENTHOF_WORM_SECRET_ACCESS_KEY\n" +
		"    token_env: AGENTHOF_WORM_SESSION_TOKEN\n" +
		"anchor: tlog\nanchor_backend: { kind: transparency-log, url: https://rekor.sigstore.dev }\n"
	got, err := ParseIntegrity([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	want := wormBackend(nil)
	want.Anchor = "tlog"
	want.AnchorBackend = IntegrityBackend{Kind: "transparency-log", URL: "https://rekor.sigstore.dev"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded\n got %+v\nwant %+v", got, want)
	}
}

// TestAnchorRunsValues: anchor_runs absent reads as "", none and on-demand are
// accepted under anchor: tlog, and every other value, or on-demand without
// tlog, is refused by name. Matched exactly: no case-folding.
func TestAnchorRunsValues(t *testing.T) {
	const tlog = "anchor: tlog\nanchor_backend:\n  url: https://log.example\n"
	for body, want := range map[string]string{
		"":                                "",
		tlog:                              "",
		tlog + "anchor_runs: none\n":      "none",
		tlog + "anchor_runs: on-demand\n": "on-demand",
	} {
		in, err := ParseIntegrity([]byte(body))
		if err != nil {
			t.Errorf("ParseIntegrity(%q) = %v, want nil", body, err)
			continue
		}
		if in.AnchorRuns != want {
			t.Errorf("ParseIntegrity(%q).AnchorRuns = %q, want %q", body, in.AnchorRuns, want)
		}
	}
	const noTlog = "anchor_runs is set but anchor is none; run anchoring uses the anchor_backend that anchor: tlog names"
	for body, want := range map[string]string{
		tlog + "anchor_runs: each\n":             `anchor_runs "each" is not a run-anchoring mode (want none or on-demand)`,
		tlog + "anchor_runs: On-Demand\n":        `anchor_runs "On-Demand" is not a run-anchoring mode (want none or on-demand)`,
		"anchor_runs: on-demand\n":               noTlog,
		"anchor: none\nanchor_runs: on-demand\n": noTlog,
	} {
		_, err := ParseIntegrity([]byte(body))
		if err == nil || !strings.HasSuffix(err.Error(), want) {
			t.Errorf("ParseIntegrity(%q) = %v, want an error ending %q", body, err, want)
		}
	}
}

// TestAnchorRunsIsAKnownKey: anchor_runs passes the fail-closed key check; a
// near-miss is refused with the new allowed-keys text.
func TestAnchorRunsIsAKnownKey(t *testing.T) {
	if _, err := ParseIntegrity([]byte("anchor_runs: none\n")); err != nil {
		t.Errorf("anchor_runs: none = %v, want nil", err)
	}
	const want = `line 1: unknown key "anchor_run" (allowed keys: sink, anchor, anchor_runs, duplicate, sink_backend, anchor_backend)`
	if _, err := ParseIntegrity([]byte("anchor_run: none\n")); err == nil || err.Error() != want {
		t.Errorf("anchor_run: none = %v, want %q", err, want)
	}
}
