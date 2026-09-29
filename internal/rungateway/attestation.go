package rungateway

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"unicode"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/agenthof/agenthof/internal/engine"
)

// runtimeAttestationMetaKey is the _meta key a trusted runtime sets on every
// CallToolResult it relays (refbridge: deploy/refbridge/bridge.go). _meta is
// the field MCP reserves for exactly this, and the key is namespaced per the
// protocol's general-fields rule. The value's shape is engine.RuntimeAttestation's
// JSON. It is a pinned wire contract: nothing is imported across the
// internal/ boundary in either direction.
const runtimeAttestationMetaKey = "agenthof.dev/runtime-attestation"

// runtimeRefbridge is the only trusted runtime the door knows.
const runtimeRefbridge = "refbridge"

// Caps on what a runtime may put in the ledger: the attestation is
// upstream-controlled bytes even from a trusted party.
const (
	maxAttestedArgv     = 32
	maxAttestedEnvNames = 64
	maxAttestedRunes    = 200 // per argv element and for the session id — the ledger's usual bound
)

var (
	errAttestationMissing   = errors.New("runtime attestation missing")
	errAttestationMalformed = errors.New("runtime attestation malformed")
	envNameRE               = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// takeRuntimeAttestation removes the runtime attestation from result's _meta
// — always, so the agent never sees it and hashResult never covers it — and
// decides what the ledger gets. declared is the resource's Runtime: "" means
// the resource is an ordinary MCP server, so any attestation it sends is a
// claim to a trust it was not given and is dropped (dropped reports that, so
// the caller can log it); "refbridge" means the operator declared a trusted
// runtime, so a result must carry a well-formed attestation and a missing or
// malformed one is an error the caller turns into a failed call. Errors are
// fixed strings: the raw value never reaches a reason or a log line.
func takeRuntimeAttestation(result *mcp.CallToolResult, declared string) (att *engine.RuntimeAttestation, dropped bool, err error) {
	var raw any
	present := false
	if result != nil {
		raw, present = result.Meta[runtimeAttestationMetaKey]
		if present {
			delete(result.Meta, runtimeAttestationMetaKey)
			if len(result.Meta) == 0 {
				result.Meta = nil
			}
		}
	}
	if declared == "" {
		return nil, present, nil
	}
	if !present {
		return nil, false, errAttestationMissing
	}
	// The SDK decoded _meta into map[string]any; a marshal/unmarshal round
	// trip is the one decoder for the typed shape. A fractional pid or a
	// non-object value fails here, and unknown keys are ignored (additive).
	data, err := json.Marshal(raw)
	if err != nil {
		return nil, false, errAttestationMalformed
	}
	var a engine.RuntimeAttestation
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, false, errAttestationMalformed
	}
	if !validAttestation(&a, declared) {
		return nil, false, errAttestationMalformed
	}
	return &a, false, nil
}

func validAttestation(a *engine.RuntimeAttestation, declared string) bool {
	if a.Runtime != declared || a.Runtime != runtimeRefbridge {
		return false
	}
	if len([]rune(a.Session)) > maxAttestedRunes || hasControl(a.Session) {
		return false
	}
	if len(a.Command) == 0 || len(a.Command) > maxAttestedArgv {
		return false
	}
	for _, arg := range a.Command {
		if len([]rune(arg)) > maxAttestedRunes || hasControl(arg) {
			return false
		}
	}
	if a.PID < 1 || a.Spawn < 1 {
		return false
	}
	if !envNameRE.MatchString(a.CredentialEnv) {
		return false
	}
	if len(a.EnvNames) > maxAttestedEnvNames {
		return false
	}
	for _, name := range a.EnvNames {
		if !envNameRE.MatchString(name) {
			return false
		}
	}
	switch a.Materialization {
	case "env-at-spawn", "respawn-on-rotation":
		return true
	}
	return false
}

// hasControl reports whether s holds a control character: a newline or
// escape in an attested string would forge structure in whatever renders it.
func hasControl(s string) bool {
	return strings.ContainsFunc(s, unicode.IsControl)
}
