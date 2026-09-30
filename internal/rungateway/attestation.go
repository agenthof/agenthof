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

// knownRuntimes are the trusted runtimes the doors know, keyed by the value
// the operator declares (ToolResource.Runtime, ExecConfig.Runtime), which
// must equal the value the runtime speaks in its attestation.
var knownRuntimes = map[string]bool{"refbridge": true, "refexec": true}

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
	att, err = decodeAttestation(raw, declared)
	return att, false, err
}

// decodeAttestation turns a runtime's attestation as decoded from JSON — raw
// is a map[string]any with numbers as float64 — into the typed shape and
// validates it against the runtime the operator declared. It is
// transport-neutral: the tool door hands it the value it took out of _meta,
// the exec door the runtime_attestation member of refexec's response. A nil
// raw is a missing attestation. Unknown keys are ignored (additive); a
// fractional pid or a non-object value is malformed. Errors are fixed
// strings: the raw value never reaches a reason or a log line.
func decodeAttestation(raw any, declared string) (*engine.RuntimeAttestation, error) {
	if raw == nil {
		return nil, errAttestationMissing
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return nil, errAttestationMalformed
	}
	var a engine.RuntimeAttestation
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, errAttestationMalformed
	}
	if !validAttestation(&a, declared) {
		return nil, errAttestationMalformed
	}
	return &a, nil
}

func validAttestation(a *engine.RuntimeAttestation, declared string) bool {
	if a.Runtime != declared || !knownRuntimes[a.Runtime] {
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
	if len(a.EnvNames) > maxAttestedEnvNames {
		return false
	}
	for _, name := range a.EnvNames {
		if !envNameRE.MatchString(name) || len([]rune(name)) > maxAttestedRunes {
			return false
		}
	}
	// The credential fields are refbridge's: it materializes a credential
	// into its child and says where. refexec is credential-less and must say
	// so — a refexec claiming a credential variable is not the contract.
	if a.Runtime == "refexec" {
		return a.CredentialEnv == "" && a.Materialization == ""
	}
	if !envNameRE.MatchString(a.CredentialEnv) || len([]rune(a.CredentialEnv)) > maxAttestedRunes {
		return false
	}
	switch a.Materialization {
	case "env-at-spawn", "respawn-on-rotation":
		return true
	}
	return false
}

// argvRecordable reports whether argv fits the ledger's argv bounds — exactly
// the bounds validAttestation enforces on an attested Command. The exec door
// checks this before it runs a command, so a command the ledger cannot carry
// is refused up front rather than run first and then rejected after the fact.
func argvRecordable(argv []string) bool {
	if len(argv) == 0 || len(argv) > maxAttestedArgv {
		return false
	}
	for _, a := range argv {
		if len([]rune(a)) > maxAttestedRunes || hasControl(a) {
			return false
		}
	}
	return true
}

// hasControl reports whether s holds a control character: a newline or
// escape in an attested string would forge structure in whatever renders it.
func hasControl(s string) bool {
	return strings.ContainsFunc(s, unicode.IsControl)
}
