package config

import (
	"errors"
	"fmt"
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
// Integrity built in Go: the fixed-order rules of the design, first fault
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
