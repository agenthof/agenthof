package engine

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/ledger"
)

type Binding struct {
	Invoker  identity.Invoker `json:"invoker"`
	Role     string           `json:"role"`
	Workflow string           `json:"workflow"`
	RunID    string           `json:"run_id"`
	// ParentRunID and Depth link a spawned child run to the run that asked
	// for it: the parent's run id, and how deep in the delegation tree this
	// run sits (a root run is 0; its children are 1). Both are absent on a
	// root run's events. Additive (Article VI). The binding is forwarded to
	// the agent as request headers and recorded on every event; it is not
	// signed.
	ParentRunID string `json:"parent_run_id,omitempty"`
	Depth       int    `json:"depth,omitempty"`
}

// linkedTo returns b linked under parent: parent's run id as ParentRunID and
// parent's depth + 1 as Depth. A nil parent leaves b a root. Run and Refuse
// both apply it, so a refused child records its linkage exactly like a run
// one.
func (b Binding) linkedTo(parent *Binding) Binding {
	if parent == nil {
		return b
	}
	b.ParentRunID = parent.RunID
	b.Depth = parent.Depth + 1
	return b
}

// RuntimeAttestation is a trusted operator runtime's first-hand account of
// one call it served: refbridge's, on a tool_call, or refexec's, on an exec.
// Names, ids and argv only — never a credential value, never a result or
// output body (Article III).
type RuntimeAttestation struct {
	Runtime         string   `json:"runtime"`         // "refbridge" | "refexec"
	Session         string   `json:"session"`         // refbridge: its MCP session id; refexec: the per-request id, also the compartment's name — the key into the runtime's own log
	Command         []string `json:"command"`         // the argv the runtime was asked to run
	PID             int      `json:"pid"`             // the process the runtime holds first-hand: refbridge's child, or refexec's `podman run` client on the host — never a pid inside a compartment
	Spawn           int      `json:"spawn"`           // refbridge: children spawned in this session so far (increments on a rotation respawn); refexec: always 1
	CredentialEnv   string   `json:"credential_env"`  // refbridge: the NAME of the variable the credential was materialized into; refexec: empty (credential-less)
	EnvNames        []string `json:"env_names"`       // the variable NAMES the runtime set on the process, sorted; refbridge: the child's whole environment; refexec: what it injected — an image's own ENV layer is not seen by refexec
	Materialization string   `json:"materialization"` // refbridge: env-at-spawn | respawn-on-rotation; refexec: empty
}

type Event struct {
	Time             time.Time `json:"time"`
	Type             string    `json:"type"`
	Step             string    `json:"step,omitempty"`
	Agent            string    `json:"agent,omitempty"`
	Status           string    `json:"status,omitempty"`
	Reason           string    `json:"reason,omitempty"`
	Artifact         string    `json:"artifact,omitempty"`     // for tool_call, reused to carry a short preview of the tool result
	ArtifactSHA      string    `json:"artifact_sha,omitempty"` // for tool_call, reused to carry the sha256 of the tool result
	Execution        string    `json:"execution,omitempty"`
	ConfigHash       string    `json:"config_hash,omitempty"`
	AuthMode         string    `json:"auth_mode,omitempty"`         // set by tool_call to the resource's credential mode, e.g. "static_env"
	ResourcesTouched []string  `json:"resources_touched,omitempty"` // set by tool_call to the touched tool resource's id; still reserved for a future multi-resource call
	Tool             string    `json:"tool,omitempty"`              // set by tool_call: the tool name invoked (or attempted)
	ArgsSHA          string    `json:"args_sha,omitempty"`          // set by tool_call: sha256 of the raw call arguments (never the args themselves)
	Command          []string  `json:"command,omitempty"`           // set by exec: the reported argv
	ExitCode         *int      `json:"exit_code,omitempty"`         // set by exec: pointer so 0 (success) is distinct from absent
	OutputSHA        string    `json:"output_sha,omitempty"`        // set by exec: the runtime's sha256 of the output it returned (on a historical attested event, the hash the agent reported); set by spawn: sha256 of the child's final artifact; never the output or the artifact
	Mode             string    `json:"mode,omitempty"`              // set by exec: "runtime" (a declared runtime ran it first-hand; see RuntimeAttestation). Ledgers written before exec became first-hand only carry "attested" (the agent's own report); the field is read and rendered verbatim
	Model            string    `json:"model,omitempty"`             // set by model_call: the logical model requested
	PromptTokens     *int      `json:"prompt_tokens,omitempty"`     // set by model_call (non-streaming): usage
	CompletionTokens *int      `json:"completion_tokens,omitempty"` // set by model_call (non-streaming): usage
	ChildRunID       string    `json:"child_run_id,omitempty"`      // set by spawn: the child run this event links to, whenever one was started (absent when the door refused before starting one)
	ChildRole        string    `json:"child_role,omitempty"`        // set by spawn: the role the child ran, or was asked to run, as
	ChildWorkflow    string    `json:"child_workflow,omitempty"`    // set by spawn: the child's workflow
	Depth            int       `json:"depth,omitempty"`             // set by spawn: the child's depth in the delegation tree (this run's depth + 1)
	// RuntimeAttestation is set by tool_call when the resource declares a
	// trusted runtime (runtime: refbridge) and by exec, whose door is
	// first-hand (served by refexec): that runtime's FIRST-HAND account of
	// the call — which command it ran, which process it held, with which
	// environment variable NAMES. It is the runtime's word, not the agent's
	// (a historical exec event with Mode "attested" is the agent's, and
	// carries none), and never a value.
	RuntimeAttestation *RuntimeAttestation `json:"runtime_attestation,omitempty"`
	Actor              string              `json:"actor,omitempty"`     // reserved: delegation — the acting agent
	Principal          string              `json:"principal,omitempty"` // reserved: delegation — the initiating human/system
	// Origin is set by workflow_started and run_refused when the run arrived
	// over the API: the request channel's provenance (never a witness;
	// forwarded_for is unverified). Absent on every CLI run.
	Origin  *Origin `json:"origin,omitempty"`
	Binding Binding `json:"binding"`
	Prev    string  `json:"prev"`
}

func NewRunID() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failing means the host is broken
	}
	return "r-" + hex.EncodeToString(b)
}

type Log struct {
	mu sync.Mutex
	c  *ledger.Chain
}

// OpenLog creates the run's log file and opens it for writing. Because
// ledger.Open resumes an existing file's chain rather than rejecting it,
// OpenLog itself refuses a run ID whose file already has events — without
// this guard, a colliding run ID would silently chain a second run's
// events onto the first run's log, and audit would misattribute them.
// A Log is opened exactly once per fresh run file; run logs are Unlocked
// because each has one writer process. Concurrent in-process appenders
// (e.g. the engine and the run gateway) are serialized by Log.mu.
func OpenLog(dir, runID string) (*Log, error) {
	c, err := ledger.Open(filepath.Join(dir, runID+".jsonl"), ledger.Unlocked)
	if err != nil {
		return nil, err
	}
	if c.Count() != 0 {
		_ = c.Close()
		return nil, fmt.Errorf("run %s: log already exists", runID)
	}
	return &Log{c: c}, nil
}

func (l *Log) Append(e Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	e.Prev = l.c.Prev()
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return l.c.Append(data)
}

func (l *Log) Close() error { return l.c.Close() }

// ReadLog loads and verifies the run's ledger. On a torn or broken chain
// it still returns the parsed valid prefix of events alongside that
// prefix's Head and the typed ledger error (*ledger.TornError or
// *ledger.ChainBrokenError), never just a bare error — a caller can
// decide how to proceed. On an open/IO failure it returns
// (nil, ledger.Head{}, err) wrapped as today.
func ReadLog(dir, runID string) ([]Event, ledger.Head, error) {
	recs, head, verr := ledger.ReadVerify(filepath.Join(dir, runID+".jsonl"), ledger.Unlocked)
	if recs == nil && verr != nil {
		var te *ledger.TornError
		var be *ledger.ChainBrokenError
		if !errors.As(verr, &te) && !errors.As(verr, &be) {
			return nil, ledger.Head{}, fmt.Errorf("run %s: %w", runID, verr) // open/IO failure, as today
		}
	}
	out := make([]Event, 0, len(recs))
	for i, r := range recs {
		var e Event
		if err := json.Unmarshal(r.Raw, &e); err != nil {
			// head (from ledger.ReadVerify) counts every ledger-valid raw
			// record, which can run past i when a later record is
			// chain-valid but not Event-decodable; every other return
			// path holds head.Count == len(events), so Count is
			// corrected to len(out) here too. Hash is set to "" rather
			// than the full verified chain's head hash, since
			// ledger.ReadVerify never computed one scoped to just the
			// decoded prefix and a Hash/Count pair that disagree would
			// be self-inconsistent.
			return out, ledger.Head{Hash: "", Count: len(out)}, &ledger.ChainBrokenError{Line: i + 1} // parseable-for-chain but not an Event
		}
		out = append(out, e)
	}
	return out, head, verr
}
