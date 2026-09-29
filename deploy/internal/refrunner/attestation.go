package refrunner

// AttestationMetaKey is the MCP _meta key under which a runtime that relays
// tool results (refbridge) attaches its attestation; the gateway reads it in
// internal/rungateway/attestation.go. refexec carries the same shape as the
// runtime_attestation member of its /run response instead. Pinned wire
// contract; nothing is imported across the internal/ boundary.
const AttestationMetaKey = "agenthof.dev/runtime-attestation"

// Attestation is what a runtime knows FIRST-HAND about the process that
// served a call: it built the environment, spawned the process, and relayed
// the call or captured its output. Names, ids and argv only — never a
// credential's value, never an output body. Runtime names the party
// speaking; the gateway checks it against the runtime the operator declared.
// The credential fields are refbridge's; refexec is credential-less and
// leaves them empty.
type Attestation struct {
	Runtime         string   // "refbridge" | "refexec"
	Session         string   // refbridge: the MCP session id; refexec: the per-request id, which is also the compartment's name
	Command         []string // the argv the runtime was asked to run
	PID             int      // the process the runtime holds first-hand: refbridge's stdio child, or refexec's `podman run` client — never a pid inside a compartment
	Spawn           int      // refbridge: the child's 1-based generation within the session; refexec: always 1
	CredentialEnv   string   // refbridge only: the NAME of the variable the credential was materialized into
	EnvNames        []string // the variable NAMES the runtime itself set on the process, sorted; an image's own ENV layer is not included — the runtime never sees it
	Materialization string   // refbridge only: env-at-spawn | respawn-on-rotation
}

// Meta is the wire form: exactly the keys internal/rungateway decodes.
func (a Attestation) Meta() map[string]any {
	return map[string]any{
		"runtime":         a.Runtime,
		"session":         a.Session,
		"command":         a.Command,
		"pid":             a.PID,
		"spawn":           a.Spawn,
		"credential_env":  a.CredentialEnv,
		"env_names":       a.EnvNames,
		"materialization": a.Materialization,
	}
}
