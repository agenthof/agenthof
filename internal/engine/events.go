package engine

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
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
	Time        time.Time `json:"time"`
	Type        string    `json:"type"`
	Step        string    `json:"step,omitempty"`
	Agent       string    `json:"agent,omitempty"`
	Status      string    `json:"status,omitempty"`
	Reason      string    `json:"reason,omitempty"`
	Artifact    string    `json:"artifact,omitempty"`
	ArtifactSHA string    `json:"artifact_sha,omitempty"`
	Execution   string    `json:"execution,omitempty"`
	Binding     Binding   `json:"binding"`
	Prev        string    `json:"prev"`
}

func NewRunID() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failing means the host is broken
	}
	return "r-" + hex.EncodeToString(b)
}

type Log struct{ c *ledger.Chain }

// OpenLog creates the run's log file and opens it for writing. Because
// ledger.Open resumes an existing file's chain rather than rejecting it,
// OpenLog itself refuses a run ID whose file already has events — without
// this guard, a colliding run ID would silently chain a second run's
// events onto the first run's log, and audit would misattribute them.
// A Log is opened exactly once per fresh run file; run logs are Unlocked
// because each has one writer.
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
