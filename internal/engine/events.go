package engine

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
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

// OpenLog opens (or creates) the run's log file, resuming the chain from
// wherever it left off — Open itself replays and verifies the existing
// file, so a Log may be safely (re)opened at any point in a run's life,
// not just once against a fresh file. Run logs use ledger.Unlocked
// because each run file has exactly one writer by construction and
// live-run audits must not block.
func OpenLog(dir, runID string) (*Log, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	c, err := ledger.Open(filepath.Join(dir, runID+".jsonl"), ledger.Unlocked)
	if err != nil {
		return nil, err
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
			// corrected to len(out) here too. Hash is left as the full
			// verified chain's head hash (ledger.ReadVerify never
			// computed one scoped to just the decoded prefix).
			return out, ledger.Head{Hash: head.Hash, Count: len(out)}, &ledger.ChainBrokenError{Line: i + 1} // parseable-for-chain but not an Event
		}
		out = append(out, e)
	}
	return out, head, verr
}
