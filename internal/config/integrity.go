package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Integrity is a control root's integrity posture — the two-knob seam of the
// integrity design: Sink is where the ledger's bytes live (prevention), Anchor
// is what pins its head (third-party attestation, layerable on any sink). It
// is read from integrity.yaml beside the control ledger; absent means the
// floor. The floor — sink "local", anchor "none", nothing else set — and
// anchor "tlog" with a transparency-log backend are implemented, as is sink
// "worm" with an s3-object-lock backend: the floor is exactly the hash-chained
// local file the constitution describes. Every other value is RESERVED:
// parsed, named, and refused by Validate, never read as the floor (a posture
// nothing honours would be a false guarantee). Backend coordinates are broker
// references — env-var NAMES, never values (Article II).
type Integrity struct {
	Sink   string `yaml:"sink"`   // "" | "local" (the floor) | "worm" | "external" (reserved)
	Anchor string `yaml:"anchor"` // "" | "none" (the floor) | "tlog" | "signed" (reserved)
	// AnchorRuns is whether a single run's ledger may be anchored on demand:
	// "" | "none" (the floor) | "on-demand". Only `audit anchor` reads it;
	// `run` and every reader stay posture-blind.
	AnchorRuns string `yaml:"anchor_runs"`
	// Duplicate is reserved: further sinks written in parallel with Sink
	// (a separately stored duplicate copy). Must be empty.
	Duplicate []IntegrityBackend `yaml:"duplicate"`
	// SinkBackend holds the coordinates of a worm sink (kind s3-object-lock);
	// external is reserved. Must be unset while Sink is local. AnchorBackend holds the coordinates
	// of a transparency log (anchor: tlog); the other anchor kinds (timestamp
	// authority, signing key) are reserved. Must be unset while Anchor is none.
	SinkBackend   IntegrityBackend `yaml:"sink_backend"`
	AnchorBackend IntegrityBackend `yaml:"anchor_backend"`
}

// IntegrityBackend names an external integrity service and how to reach it.
// Kind "transparency-log" is implemented for anchor: tlog and "s3-object-lock"
// for sink: worm; every other kind is reserved. URL is the service's public
// endpoint or key URI (a KMS key ARN/URI fits; never a secret, and never a
// parallel key field later); Credential is the broker reference it
// authenticates with.
type IntegrityBackend struct {
	Kind string `yaml:"kind"` // "s3-object-lock", "transparency-log" (implemented); reserved vocabulary, e.g. "rfc3161", "kms"
	URL  string `yaml:"url"`  // the service's endpoint OR key URI
	// Region, Mode and Retention are the coordinates of a write-once store
	// (s3-object-lock): the signing region (derived when empty), the lock
	// mode (compliance only) and how long a sealed segment is locked.
	// They are refused on an anchor backend.
	Region     string            `yaml:"region"`
	Mode       string            `yaml:"mode"`
	Retention  string            `yaml:"retention"`
	Credential BackendCredential `yaml:"credential"`
}

// IsSet reports whether any coordinate is present, the credential's
// included — the ExecConfig.Declared rule: a half-filled block is declared,
// never silently ignored.
func (b IntegrityBackend) IsSet() bool { return b != (IntegrityBackend{}) }

// BackendCredential is a broker reference in configuration: the three-axis
// shape (credential_source × grant_type × client_auth) ToolResource already
// spells, field for field, so an operator learns one credential vocabulary.
// Every secret coordinate is an environment-variable NAME. It maps onto
// broker.CredentialRef at the point of use — `audit anchor` is its first consumer.
type BackendCredential struct {
	CredentialSource string `yaml:"credential_source"` // "static_env" | reserved
	TokenEnv         string `yaml:"token_env"`         // direct-bearer: env NAME
	GrantType        string `yaml:"grant_type"`        // "" | "client_credentials" | "token_exchange"
	ClientAuth       string `yaml:"client_auth"`
	Issuer           string `yaml:"issuer"`
	TokenEndpoint    string `yaml:"token_endpoint"`
	ClientIDEnv      string `yaml:"client_id_env"`     // env NAME
	ClientSecretEnv  string `yaml:"client_secret_env"` // env NAME
	Scope            string `yaml:"scope"`
	Audience         string `yaml:"audience"`
}

// Validate is ParseIntegrity's second half, exported for callers that hold an
// Integrity built in Go: the fixed-order rules below, first fault only —
// sink, then anchor, then anchor_runs, then duplicate, then the two backends.
// A value is matched exactly (case-sensitive, no trimming): config is law, not a guess.
// Since every reserved sink and anchor is refused first, the backend rules
// can only fire at the floor — except sink_backend under sink: worm and
// anchor_backend under anchor: tlog, which are those postures' own
// coordinates and are validated as part of their cases. Coordinates naming a
// backend nothing consumes would be a false signal to a reader of the file.
func (i Integrity) Validate() error {
	switch i.Sink {
	case "", "local":
	case "worm":
		if err := validateSinkBackend(i.SinkBackend); err != nil {
			return err
		}
	case "external":
		return fmt.Errorf("sink %q is reserved and not yet supported in this build (only local and worm are implemented)", i.Sink)
	case "duplicate":
		// A sink VALUE in the design's vocabulary, so the operator is early,
		// not wrong — but the shape spells it as the list.
		return errors.New(`sink "duplicate" is reserved and not yet supported in this build; when it is, it is written as the duplicate: list, not as the sink value`)
	default:
		return fmt.Errorf("sink %q is not an integrity sink (want local or worm; external and duplicate are reserved)", i.Sink)
	}
	switch i.Anchor {
	case "", "none":
	case "signed":
		return errors.New(`anchor "signed" is reserved and not yet supported in this build (only none and tlog are implemented)`)
	case "tlog":
		if err := validateAnchorBackend(i.AnchorBackend); err != nil {
			return err
		}
	default:
		return fmt.Errorf("anchor %q is not an integrity anchor (want none or tlog; signed is reserved)", i.Anchor)
	}
	switch i.AnchorRuns {
	case "", "none":
	case "on-demand":
		if i.Anchor != "tlog" {
			return errors.New("anchor_runs is set but anchor is none; run anchoring uses the anchor_backend that anchor: tlog names")
		}
	default:
		return fmt.Errorf("anchor_runs %q is not a run-anchoring mode (want none or on-demand)", i.AnchorRuns)
	}
	if n := len(i.Duplicate); n > 0 {
		return fmt.Errorf("duplicate names %d sink(s); duplicate sinks are reserved and not yet supported in this build", n)
	}
	if i.Sink != "worm" && i.SinkBackend.IsSet() {
		return errors.New("sink_backend is set but sink is local; backend coordinates belong to worm (and to external, which is reserved)")
	}
	if i.Anchor != "tlog" && i.AnchorBackend.IsSet() {
		return errors.New("anchor_backend is set but anchor is none; backend coordinates are reserved for tlog and signed")
	}
	return nil
}

// validateAnchorBackend checks anchor: tlog's own coordinates — the ones the
// anchoring command consumes — reporting the first fault in a fixed order
// (kind, url, the write-once coordinates it refuses, then the credential
// fields). The credential check is shape-only
// on purpose: it does not check that client_credentials has its endpoint and
// env names — the broker fails at use with its own named error, and audit
// anchor records that as an anchor error. Validation is syntactic: no
// network, no DNS; the first contact with the log is the
// command.
func validateAnchorBackend(b IntegrityBackend) error {
	if !b.IsSet() {
		return errors.New("anchor is tlog but anchor_backend is not set; name the transparency log (kind transparency-log, url)")
	}
	switch b.Kind {
	case "", "transparency-log":
	case "rfc3161":
		return errors.New(`anchor_backend kind "rfc3161" is reserved and not yet supported in this build (only transparency-log is implemented)`)
	default:
		return fmt.Errorf("anchor_backend kind %q is not an anchor backend kind (want transparency-log; rfc3161 is reserved)", b.Kind)
	}
	if b.URL == "" {
		return errors.New("anchor_backend.url is required for anchor: tlog (the Sigstore public-good log is https://rekor.sigstore.dev)")
	}
	if !isBackendURL(b.URL) {
		return fmt.Errorf("anchor_backend.url %q is not an absolute http(s) URL without credentials", b.URL)
	}
	for _, coord := range []struct{ name, value string }{{"region", b.Region}, {"mode", b.Mode}, {"retention", b.Retention}} {
		if coord.value != "" {
			return fmt.Errorf("anchor_backend.%s is not a coordinate of an anchor backend", coord.name)
		}
	}
	c := b.Credential
	switch c.GrantType {
	case "", "client_credentials":
	default:
		return fmt.Errorf("anchor_backend.credential: grant_type %q is not supported for an anchor backend (want client_credentials, or a direct bearer via token_env)", c.GrantType)
	}
	switch c.CredentialSource {
	case "", "static_env":
	default:
		return fmt.Errorf("anchor_backend.credential: credential_source %q is not supported for an anchor backend (want static_env)", c.CredentialSource)
	}
	return nil
}

// The retention bounds of a write-once sink. A year is a fixed 365 days: a
// leap-year-exact year is nobody's compliance requirement, and a fixed day
// count keeps a retain-until date recomputable. The minimum is the day S3
// itself imposes; any policy floor above it is the operator's.
const (
	RetentionDay  = 24 * time.Hour
	RetentionYear = 365 * RetentionDay
	RetentionMin  = RetentionDay
	RetentionMax  = 100 * RetentionYear
)

var (
	retentionForm = regexp.MustCompile(`^([1-9][0-9]*)(d|y)$`)
	regionName    = regexp.MustCompile(`^[a-z0-9-]+$`)
)

// ParseRetention reads <n>d or <n>y — the one place that grammar is read —
// into a duration within [RetentionMin, RetentionMax]. The errors name the
// sink_backend.retention key: that is the only place a retention is written.
func ParseRetention(s string) (time.Duration, error) {
	if s == "" {
		return 0, errors.New("sink_backend.retention is required for s3-object-lock: <n>d or <n>y (e.g. 7y)")
	}
	m := retentionForm.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("sink_backend.retention %q is not a retention (want <n>d or <n>y)", s)
	}
	unit := RetentionDay
	if m[2] == "y" {
		unit = RetentionYear
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	// Compare in units before multiplying, so a huge n cannot wrap a Duration.
	if err != nil || n > int64(RetentionMax/unit) {
		return 0, fmt.Errorf("sink_backend.retention %q exceeds 100y", s)
	}
	d := time.Duration(n) * unit
	if d < RetentionMin { // unreachable by the grammar (1d is the smallest form); kept so the bound is stated
		return 0, fmt.Errorf("sink_backend.retention %q is below the minimum of 1d", s)
	}
	return d, nil
}

// validateSinkBackend checks sink: worm's own coordinates — the ones the seal
// consumes — reporting the first fault in a fixed order (set, kind, url,
// mode, retention, region, then the credential). Only compliance mode is
// accepted: a governance-mode lock can be lifted by a privileged user. Like
// the anchor's, the check is syntactic: no network, no DNS, and that the named
// env vars are set is the broker's verdict at use.
func validateSinkBackend(b IntegrityBackend) error {
	if !b.IsSet() {
		return errors.New("sink is worm but sink_backend is not set; name the write-once store (kind s3-object-lock, url, mode compliance, retention)")
	}
	switch b.Kind {
	case "s3-object-lock":
	case "azure-immutable-blob", "gcs-bucket-lock":
		return fmt.Errorf("sink_backend kind %q is reserved and not yet supported in this build (only s3-object-lock is implemented)", b.Kind)
	default:
		return fmt.Errorf("sink_backend kind %q is not a write-once sink kind (want s3-object-lock; azure-immutable-blob and gcs-bucket-lock are reserved)", b.Kind)
	}
	if b.URL == "" {
		return errors.New("sink_backend.url is required for sink: worm (endpoint + /bucket[/prefix], e.g. https://s3.<region>.amazonaws.com/<bucket>)")
	}
	if !isBackendURL(b.URL) {
		return fmt.Errorf("sink_backend.url %q is not an absolute http(s) URL without credentials", b.URL)
	}
	if u, err := url.Parse(b.URL); err != nil || strings.Trim(u.Path, "/") == "" {
		return fmt.Errorf("sink_backend.url %q names no bucket (want endpoint + /bucket[/prefix])", b.URL)
	}
	switch b.Mode {
	case "compliance":
	case "":
		return errors.New("sink_backend.mode is required for s3-object-lock and must be compliance (governance mode can be lifted by a privileged user and is refused)")
	case "governance":
		return errors.New(`sink_backend.mode "governance" is refused: a governance-mode lock can be bypassed by a privileged user; use compliance`)
	default:
		return fmt.Errorf("sink_backend.mode %q is not an object-lock mode (want compliance)", b.Mode)
	}
	if _, err := ParseRetention(b.Retention); err != nil {
		return err
	}
	if b.Region != "" && !regionName.MatchString(b.Region) {
		return fmt.Errorf("sink_backend.region %q is not a region name", b.Region)
	}
	c := b.Credential
	switch c.CredentialSource {
	case "", "static_env":
	default:
		return fmt.Errorf("sink_backend.credential: credential_source %q is not supported for a write-once sink (want static_env)", c.CredentialSource)
	}
	if c.GrantType != "" {
		return fmt.Errorf("sink_backend.credential: grant_type %q is not supported for a write-once sink (a signing key pair is used directly; leave grant_type unset)", c.GrantType)
	}
	if c.ClientAuth != "sigv4" {
		return errors.New("sink_backend.credential: client_auth must be sigv4 for s3-object-lock")
	}
	if c.ClientIDEnv == "" || c.ClientSecretEnv == "" {
		return errors.New("sink_backend.credential: client_id_env and client_secret_env are required (the access key id and secret access key env NAMES)")
	}
	for _, unused := range []struct{ name, value string }{{"issuer", c.Issuer}, {"token_endpoint", c.TokenEndpoint}, {"scope", c.Scope}, {"audience", c.Audience}} {
		if unused.value != "" {
			return fmt.Errorf("sink_backend.credential: %s is not used by sigv4", unused.name)
		}
	}
	return nil
}

// isBackendURL admits an absolute http or https URL with a host and no
// userinfo, query or fragment — the same rule the anchoring client applies
// to a URL read back from a record. Kept here rather than imported so this
// package stays a leaf of its own.
func isBackendURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == ""
}

// The allowed-key lists, in the order the error texts name them. A future
// sibling key (cadence) is added here: the text is not a wire contract.
const (
	integrityKeys  = "sink, anchor, anchor_runs, duplicate, sink_backend, anchor_backend"
	backendKeys    = "kind, url, region, mode, retention, credential"
	credentialKeys = "credential_source, token_env, grant_type, client_auth, issuer, token_endpoint, client_id_env, client_secret_env, scope, audience"
)

// rawIntegrity is Integrity without its methods, so the mapping can be decoded
// with value.Decode without recursing back into UnmarshalYAML.
type rawIntegrity Integrity

// isNull reports a null node (`~`, `null`, or a key with no value): yaml.v3
// decodes it to the zero value, which is the floor for every reserved key.
func isNull(n *yaml.Node) bool { return n.Kind == yaml.ScalarNode && n.ShortTag() == "!!null" }

// UnmarshalYAML decodes an integrity.yaml document fail-closed. yaml.v3
// silently drops unknown mapping keys, so a typo like `ancher: tlog` would
// otherwise read as the floor: the keys are checked by hand first, at every
// level, and the first fault is reported with its line and position. The
// walk also guards every level that must be a mapping (or, for duplicate, a
// list): without it a scalar there would surface yaml.v3's own text naming a
// Go type. Every key must be a plain scalar: an alias- or complex-keyed
// entry (`*a : v`, `? [a]\n: v`) carries no literal name for the key check,
// so without this guard its resolved key would reach Decode, miss every
// field, and be dropped as the floor. The backend and credential shapes have no Unmarshaler of their
// own — yaml.v3 gives one no key path, and the position is what an operator
// needs — so this one walk is where their shape rules live. A null node is
// the floor and is not walked.
func (i *Integrity) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: integrity.yaml must be a mapping (allowed keys: %s)", value.Line, integrityKeys)
	}
	for k := 0; k+1 < len(value.Content); k += 2 {
		key, val := value.Content[k], value.Content[k+1]
		if key.Kind != yaml.ScalarNode {
			return fmt.Errorf("line %d: key must be a plain scalar (allowed keys: %s)", key.Line, integrityKeys)
		}
		switch key.Value {
		case "sink", "anchor", "anchor_runs":
		case "duplicate":
			if isNull(val) {
				continue
			}
			if val.Kind != yaml.SequenceNode {
				return fmt.Errorf("line %d: duplicate must be a list of backends (each a mapping; allowed keys: %s)", val.Line, backendKeys)
			}
			for n, entry := range val.Content {
				if err := checkBackendNode(entry, fmt.Sprintf("duplicate[%d]", n)); err != nil {
					return err
				}
			}
		case "sink_backend", "anchor_backend":
			if isNull(val) {
				continue
			}
			if err := checkBackendNode(val, key.Value); err != nil {
				return err
			}
		default:
			return fmt.Errorf("line %d: unknown key %q (allowed keys: %s)", key.Line, key.Value, integrityKeys)
		}
	}
	var raw rawIntegrity
	if err := value.Decode(&raw); err != nil {
		return err
	}
	*i = Integrity(raw)
	return nil
}

// checkBackendNode applies the backend shape rules to the node at `where`
// (sink_backend, anchor_backend, or duplicate[N]): a mapping, known keys
// only, and the same for its credential. A null credential is unset.
func checkBackendNode(n *yaml.Node, where string) error {
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: %s must be a mapping (allowed keys: %s)", n.Line, where, backendKeys)
	}
	for k := 0; k+1 < len(n.Content); k += 2 {
		key, val := n.Content[k], n.Content[k+1]
		if key.Kind != yaml.ScalarNode {
			return fmt.Errorf("line %d: key must be a plain scalar in %s (allowed keys: %s)", key.Line, where, backendKeys)
		}
		switch key.Value {
		case "kind", "url", "region", "mode", "retention":
		case "credential":
			if isNull(val) {
				continue
			}
			if err := checkCredentialNode(val, where+".credential"); err != nil {
				return err
			}
		default:
			return fmt.Errorf("line %d: unknown key %q in %s (allowed keys: %s)", key.Line, key.Value, where, backendKeys)
		}
	}
	return nil
}

// checkCredentialNode applies the credential shape rules at `where`: a
// mapping whose keys are the ten broker-reference fields and nothing else —
// a key that looks like a value (`token: …`) is refused as a key.
func checkCredentialNode(n *yaml.Node, where string) error {
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: %s must be a mapping (allowed keys: %s)", n.Line, where, credentialKeys)
	}
	for k := 0; k+1 < len(n.Content); k += 2 {
		key := n.Content[k]
		if key.Kind != yaml.ScalarNode {
			return fmt.Errorf("line %d: key must be a plain scalar in %s (allowed keys: %s)", key.Line, where, credentialKeys)
		}
		switch key.Value {
		case "credential_source", "token_env", "grant_type", "client_auth", "issuer",
			"token_endpoint", "client_id_env", "client_secret_env", "scope", "audience":
		default:
			return fmt.Errorf("line %d: unknown key %q in %s (allowed keys: %s)", key.Line, key.Value, where, credentialKeys)
		}
	}
	return nil
}

// ParseIntegrity decodes and validates the bytes of an integrity.yaml. It
// reports the bare fault ("line 3: unknown key …", or a Validate rule); the
// caller names the file. Empty or comment-only bytes are the floor. It
// decodes with a yaml.Decoder, never yaml.Unmarshal: Unmarshal reads the
// FIRST document and drops the rest, so a second document saying anchor: tlog
// would be read as the floor. Exactly one document is accepted.
func ParseIntegrity(data []byte) (Integrity, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	// The first document is read as a bare node so that NO Unmarshaler runs
	// before the document count is known: the one-document rule really is
	// first, even when the first document is itself faulty.
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return Integrity{}, nil // empty / comment-only: the floor
		}
		return Integrity{}, err // a yaml syntax fault ("line N: …")
	}
	var rest any
	if err := dec.Decode(&rest); !errors.Is(err, io.EOF) {
		// A second document of any kind — a mapping, or the null document a
		// trailing bare "---" produces (err == nil there) — is refused; the
		// second document is never inspected.
		return Integrity{}, errors.New("more than one YAML document; integrity.yaml holds exactly one")
	}
	var in Integrity
	if err := doc.Decode(&in); err != nil { // the shape rules, via UnmarshalYAML
		return Integrity{}, err
	}
	if err := in.Validate(); err != nil { // the value rules
		return Integrity{}, err
	}
	if in.Anchor == "tlog" && in.AnchorBackend.Kind == "" {
		// The one default: a tlog root names a transparency log unless it says
		// otherwise. Harmless because url is still required above, and applied
		// after validation so Validate judges exactly what the file said.
		in.AnchorBackend.Kind = "transparency-log"
	}
	return in, nil
}
