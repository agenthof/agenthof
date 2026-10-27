// Package sidecar is a run's anchor proof kept beside its ledger: one
// <run-id>.anchor file of JSON lines, one line per anchoring, each naming the
// run's final event, its hash, and the external backend's receipt. The run
// ledger itself is never touched (it is closed and hash-chained); the sidecar
// is outside the chain, so it is checked structurally against the chain it
// claims to cover (Check) and then decided by the same ladder a control
// ledger's anchor goes through (anchorverify.Decide).
//
// The file is an untrusted input on every read: it is read bounded (a line
// cap, a record cap, a per-field cap) and a record is believed only after
// Check has reproduced its head from the ledger.
package sidecar

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/agenthof/agenthof/internal/anchor"
	"github.com/agenthof/agenthof/internal/atomicfile"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/ledger"
)

// RunIDRE is the shape of a run id the sidecar's file name is built from.
var RunIDRE = regexp.MustCompile(`^r-[0-9a-f]{16}$`)

const (
	// Suffix is appended to a run id to name its sidecar.
	Suffix = ".anchor"
	// LockName is the one lock file, in the log directory, that serializes
	// anchoring writers.
	LockName = ".anchor.lock"
	// MaxRecords bounds the lines of one sidecar.
	MaxRecords = 32
)

// MaxLineLen is the bufio.Scanner buffer: a hostile sidecar is read bounded,
// never with the 64 KB default. A line is readable only if it is shorter than
// this (the newline needs room), so the content bound is MaxLineLen-1 bytes. It is the field caps' sum plus slack for the
// fixed keys, the time and the anchored_by object.
const MaxLineLen = anchor.MaxProofLen + control.MaxAnchorRefLen + control.MaxAnchorBackendLen + control.MaxAnchorBackendKindLen + control.MaxAnchorBackendKeyIDLen + 1024

// Path is where runID's sidecar lives under logDir.
func Path(logDir, runID string) string { return filepath.Join(logDir, runID+Suffix) }

// LockPath is the anchoring writers' lock file under logDir.
func LockPath(logDir string) string { return filepath.Join(logDir, LockName) }

// TempPattern is the os.CreateTemp pattern Append's temp files use.
func TempPattern(runID string) string { return runID + ".anchor.tmp-*" }

// Actor is who anchored: the invoker's identity, and nothing more.
type Actor struct {
	Subject string `json:"subject"`
	Issuer  string `json:"issuer"`
	Method  string `json:"method"`
}

// Record is one anchoring of a run's ledger.
type Record struct {
	Time         time.Time `json:"time"`
	RunID        string    `json:"run_id"`
	Seq          int       `json:"seq"` // the final event's 1-based position == the ledger's record count
	Hash         string    `json:"hash"`
	Kind         string    `json:"kind"`
	BackendKind  string    `json:"backend_kind"`
	Backend      string    `json:"backend"`
	Ref          string    `json:"ref"`
	Proof        string    `json:"proof"`
	BackendKeyID string    `json:"backend_key_id,omitempty"`
	AnchoredBy   Actor     `json:"anchored_by"`
}

// fieldFault is the first field of r over its cap, as "<field> is X bytes;
// the cap is Y", or "". The caps are the control anchor permit's.
func fieldFault(r Record) string {
	for _, f := range []struct {
		name string
		n    int
		max  int
	}{
		{"proof", len(r.Proof), anchor.MaxProofLen},
		{"ref", len(r.Ref), control.MaxAnchorRefLen},
		{"backend", len(r.Backend), control.MaxAnchorBackendLen},
		{"backend_kind", len(r.BackendKind), control.MaxAnchorBackendKindLen},
		{"backend_key_id", len(r.BackendKeyID), control.MaxAnchorBackendKeyIDLen},
	} {
		if f.n > f.max {
			return fmt.Sprintf("%s is %d bytes; the cap is %d", f.name, f.n, f.max)
		}
	}
	return ""
}

// Read loads the sidecar at path. An absent file is (nil, false, nil). A file
// that exists is found, and is an error — never a partial result — when it is
// not a regular file, is empty, has more than MaxRecords lines, has a line
// over MaxLineLen or one that does not decode, has a record over a field cap,
// or cannot be read.
func Read(path string) (recs []Record, found bool, err error) {
	name := filepath.Base(path) // errors name the file, never the log directory it sits in
	st, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, pathFault(name, err)
	}
	if !st.Mode().IsRegular() {
		return nil, true, fmt.Errorf("sidecar %s is not a regular file", name)
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) { // removed between Lstat and Open
			return nil, false, nil
		}
		return nil, true, pathFault(name, err)
	}
	defer func() { _ = f.Close() }()
	// The initial capacity equals the cap: bufio.Scanner enforces the larger of
	// the two, so a smaller max would be silently widened to the capacity.
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, MaxLineLen), MaxLineLen)
	for n := 1; sc.Scan(); n++ {
		if n > MaxRecords {
			return nil, true, fmt.Errorf("sidecar %s has more than %d records", name, MaxRecords)
		}
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, true, fmt.Errorf("sidecar line %d: %v", n, err)
		}
		if fault := fieldFault(r); fault != "" {
			return nil, true, fmt.Errorf("sidecar line %d: %s", n, fault)
		}
		recs = append(recs, r)
	}
	if err := sc.Err(); err != nil {
		return nil, true, fmt.Errorf("sidecar %s: %w", name, pathUnwrap(err))
	}
	if len(recs) == 0 {
		return nil, true, fmt.Errorf("sidecar %s is empty", name)
	}
	return recs, true, nil
}

// pathUnwrap drops the *fs.PathError wrapper, whose text carries the full path.
func pathUnwrap(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// pathFault is an OS error on the sidecar, worded with the file's base name.
func pathFault(name string, err error) error {
	return fmt.Errorf("sidecar %s: %w", name, pathUnwrap(err))
}

// Append adds r after the records already at path and writes the whole file
// by atomicfile.Replace: a reader sees the old sidecar or the new one, never
// a torn line. It reads what is there first, so an unreadable existing
// sidecar is an error, never silently replaced; a record Read would refuse
// (over a field cap, or past MaxRecords) is refused here rather than written.
// Append does not lock: serializing writers is the caller's job (LockPath);
// two unlocked writers each leave a whole file, but one may lose the other's
// record.
func Append(path, runID string, r Record) error {
	if fault := fieldFault(r); fault != "" {
		return fmt.Errorf("sidecar record: %s", fault)
	}
	recs, _, err := Read(path)
	if err != nil {
		return err
	}
	if len(recs) >= MaxRecords {
		return fmt.Errorf("sidecar %s already holds %d records; the cap is %d", path, len(recs), MaxRecords)
	}
	var data []byte
	for _, x := range append(recs, r) {
		b, err := json.Marshal(x)
		if err != nil {
			return err
		}
		// >=, not >: the scanner needs room for the newline, so a line is
		// readable only below MaxLineLen. json.Marshal escapes <, > and & to
		// six bytes each, so the encoded line can exceed the decoded fields.
		if len(b) >= MaxLineLen {
			return fmt.Errorf("sidecar record for run %s serializes to %d bytes; a line must be under %d", runID, len(b), MaxLineLen)
		}
		data = append(append(data, b...), '\n')
	}
	return atomicfile.Replace(path, TempPattern(runID), data)
}

// FinalEvent reports whether chain ends at the run's final event: the last
// record decodes to workflow_finished, or to run_refused when it is also the
// only record (a refusal is a whole run in one event).
func FinalEvent(chain []ledger.Record) bool {
	if len(chain) == 0 {
		return false
	}
	var e engine.Event
	if json.Unmarshal(chain[len(chain)-1].Raw, &e) != nil {
		return false
	}
	return e.Type == "workflow_finished" || (e.Type == "run_refused" && len(chain) == 1)
}
