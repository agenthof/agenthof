package engine

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/agenthof/agenthof/internal/identity"
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

type Log struct {
	f        *os.File
	lastHash string
}

// OpenLog opens (or creates) the run's log file in append mode. lastHash
// starts as "" (the genesis hash), which is only correct because, for this
// plan, a Log is opened exactly once per fresh run file — never re-opened
// mid-run to append further events onto an existing chain. If that
// assumption ever changes, OpenLog would need to replay the file first to
// recover lastHash before any further Append call.
func OpenLog(dir, runID string) (*Log, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, runID+".jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &Log{f: f}, nil
}

func (l *Log) Append(e Event) error {
	e.Prev = l.lastHash
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if _, err := l.f.Write(append(data, '\n')); err != nil {
		return err
	}
	if err := l.f.Sync(); err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	l.lastHash = hex.EncodeToString(sum[:])
	return nil
}

func (l *Log) Close() error { return l.f.Close() }

func ReadLog(dir, runID string) ([]Event, error) {
	f, err := os.Open(filepath.Join(dir, runID+".jsonl"))
	if err != nil {
		return nil, fmt.Errorf("run %s: %w", runID, err)
	}
	defer f.Close()
	var out []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("run %s: corrupt event: %w", runID, err)
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// ChainBrokenError reports the index of the first event in a ledger whose
// Prev hash does not match the marshaled form of its predecessor. Callers
// that need the broken index programmatically (e.g. audit.Render) can
// recover it with errors.As instead of parsing the error string.
type ChainBrokenError struct{ Index int }

func (e *ChainBrokenError) Error() string {
	return fmt.Sprintf("ledger chain broken at event %d", e.Index)
}

// VerifyChain walks events and confirms each one's Prev field is the
// SHA-256 hex of the previous event's marshaled JSON (no trailing newline).
// The first event must have Prev == "". It returns nil when the chain is
// intact, or a *ChainBrokenError naming the first broken index.
func VerifyChain(events []Event) error {
	if len(events) == 0 {
		return nil
	}
	if events[0].Prev != "" {
		return &ChainBrokenError{Index: 0}
	}
	for i := 1; i < len(events); i++ {
		data, err := json.Marshal(events[i-1])
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		want := hex.EncodeToString(sum[:])
		if events[i].Prev != want {
			return &ChainBrokenError{Index: i}
		}
	}
	return nil
}
