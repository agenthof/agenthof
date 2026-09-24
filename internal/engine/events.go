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
	ExitCode         *int      `json:"exit_code,omitempty"`         // set by exec attest: pointer so 0 (success) is distinct from absent
	OutputSHA        string    `json:"output_sha,omitempty"`        // set by exec attest: sha256 of the reported command output (never the output)
	Mode             string    `json:"mode,omitempty"`              // set by exec: "attested" (enforced reserved)
	Model            string    `json:"model,omitempty"`             // set by model_call: the logical model requested
	PromptTokens     *int      `json:"prompt_tokens,omitempty"`     // set by model_call (non-streaming): usage
	CompletionTokens *int      `json:"completion_tokens,omitempty"` // set by model_call (non-streaming): usage
	Actor            string    `json:"actor,omitempty"`             // reserved: delegation — the acting agent
	Principal        string    `json:"principal,omitempty"`         // reserved: delegation — the initiating human/system
	Binding          Binding   `json:"binding"`
	Prev             string    `json:"prev"`
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
