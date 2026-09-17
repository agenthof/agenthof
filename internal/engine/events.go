package engine

import (
	"bufio"
	"crypto/rand"
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
	Time     time.Time `json:"time"`
	Type     string    `json:"type"`
	Step     string    `json:"step,omitempty"`
	Agent    string    `json:"agent,omitempty"`
	Status   string    `json:"status,omitempty"`
	Reason   string    `json:"reason,omitempty"`
	Artifact string    `json:"artifact,omitempty"`
	Binding  Binding   `json:"binding"`
}

func NewRunID() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failing means the host is broken
	}
	return "r-" + hex.EncodeToString(b)
}

type Log struct{ f *os.File }

func OpenLog(dir, runID string) (*Log, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, runID+".jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	return &Log{f: f}, nil
}

func (l *Log) Append(e Event) error {
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if _, err := l.f.Write(append(data, '\n')); err != nil {
		return err
	}
	return l.f.Sync()
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
