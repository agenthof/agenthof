package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// Integrity is a control root's integrity posture — the two-knob seam of the
// integrity design: Sink is where the ledger's bytes live (prevention), Anchor
// is what pins its head (third-party attestation, layerable on any sink). It
// is read from integrity.yaml beside the control ledger; absent means the
// floor. Only the floor — sink "local", anchor "none", nothing else set — is
// implemented: it is exactly the hash-chained local file the constitution
// describes. Every other value is RESERVED: parsed, named, and refused by
// Validate, never read as the floor (a posture nothing honours would be a
// false guarantee). Backend coordinates are broker references — env-var
// NAMES, never values (Article II).
type Integrity struct {
	Sink   string `yaml:"sink"`   // "" | "local" (the floor) | "worm" | "external" (reserved)
	Anchor string `yaml:"anchor"` // "" | "none" (the floor) | "tlog" | "signed" (reserved)
	// Duplicate is reserved: further sinks written in parallel with Sink
	// (a separately stored duplicate copy). Must be empty.
	Duplicate []IntegrityBackend `yaml:"duplicate"`
	// SinkBackend and AnchorBackend are reserved: the coordinates of a worm
	// or external sink, and of a transparency log / timestamp authority /
	// signing key. Must be unset while Sink is local and Anchor is none.
	SinkBackend   IntegrityBackend `yaml:"sink_backend"`
	AnchorBackend IntegrityBackend `yaml:"anchor_backend"`
}

// IntegrityBackend names an external integrity service and how to reach it.
// Reserved in full: no kind is implemented. URL is the service's public
// endpoint or key URI (a KMS key ARN/URI fits; never a secret, and never a
// parallel key field later); Credential is the broker reference it
// authenticates with.
type IntegrityBackend struct {
	Kind       string            `yaml:"kind"` // reserved vocabulary, e.g. "s3-object-lock", "rfc3161", "transparency-log", "kms"
	URL        string            `yaml:"url"`  // the service's endpoint OR key URI
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
// broker.CredentialRef at the point of use (none in this build).
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
// Integrity built in Go: the fixed-order rules below, first fault
// only — sink, then anchor, then duplicate, then the two backends. A value is
// matched exactly (case-sensitive, no trimming): config is law, not a guess.
// Since every non-floor sink and anchor is refused first, the backend rules
// can only fire at the floor — coordinates naming a backend nothing consumes
// would be a false signal to a reader of the file.
func (i Integrity) Validate() error {
	switch i.Sink {
	case "", "local":
	case "worm", "external":
		return fmt.Errorf("sink %q is reserved and not yet supported in this build (only local is implemented)", i.Sink)
	case "duplicate":
		// A sink VALUE in the design's vocabulary, so the operator is early,
		// not wrong — but the shape spells it as the list.
		return errors.New(`sink "duplicate" is reserved and not yet supported in this build; when it is, it is written as the duplicate: list, not as the sink value`)
	default:
		return fmt.Errorf("sink %q is not an integrity sink (want local; worm, external and duplicate are reserved)", i.Sink)
	}
	switch i.Anchor {
	case "", "none":
	case "tlog", "signed":
		return fmt.Errorf("anchor %q is reserved and not yet supported in this build (only none is implemented)", i.Anchor)
	default:
		return fmt.Errorf("anchor %q is not an integrity anchor (want none; tlog and signed are reserved)", i.Anchor)
	}
	if n := len(i.Duplicate); n > 0 {
		return fmt.Errorf("duplicate names %d sink(s); duplicate sinks are reserved and not yet supported in this build", n)
	}
	if i.SinkBackend.IsSet() {
		return errors.New("sink_backend is set but sink is local; backend coordinates are reserved for worm and external")
	}
	if i.AnchorBackend.IsSet() {
		return errors.New("anchor_backend is set but anchor is none; backend coordinates are reserved for tlog and signed")
	}
	return nil
}

// The allowed-key lists, in the order the error texts name them. A future
// sibling key (cadence, runs) is added here: the text is not a wire contract.
const (
	integrityKeys  = "sink, anchor, duplicate, sink_backend, anchor_backend"
	backendKeys    = "kind, url, credential"
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
		case "sink", "anchor":
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
		case "kind", "url":
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
	return in, nil
}
