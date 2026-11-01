package confiner

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// pidRecord is what the Seatbelt backend keeps per compartment, so a later
// process (RemoveStore, Reap) can tell the SAME process from a reused pid: the
// pid alone is never trusted, its start time must match too. The schema is
// additive: a field is only ever added, and a reader treats a missing one as
// its zero value.
type pidRecord struct {
	// PID and StartUnixMicro name the compartment's own process. PID is 0
	// while the record is PENDING: Launch claims the name — writes this record
	// with the owner below — BEFORE it starts anything, and fills the pid in
	// once the process exists, so a sweep that runs in between sees a name a
	// live instance owns rather than a scratch dir nothing accounts for.
	PID            int    `json:"pid"`
	StartUnixMicro int64  `json:"start_unix_micro"`
	Store          string `json:"store"`
	// OwnerPID and OwnerStartUnixMicro name the process that launched the
	// compartment (the backend's own process), so Reap can tell a leftover,
	// whose owner is gone, from a compartment another running instance is
	// using. A record written before these fields existed reads as owned by
	// nobody, which Reap treats as a leftover: only an instance from before
	// the stamp could have written it, and that instance has since exited.
	OwnerPID            int   `json:"owner_pid,omitempty"`
	OwnerStartUnixMicro int64 `json:"owner_start_unix_micro,omitempty"`
}

// owner is the record's owner stamp; the zero ownerRef for an unstamped record.
func (r pidRecord) owner() ownerRef {
	return ownerRef{pid: r.OwnerPID, start: r.OwnerStartUnixMicro}
}

// writePIDRecord creates path exclusively (0600): a record for a name that
// already has one is refused, never replaced, so a live compartment's record
// cannot be overwritten by a later launch under the same name. A failed write
// removes the partial file so it does not block the next attempt.
func writePIDRecord(path string, r pidRecord) error {
	body, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("confiner: encode pid record: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("confiner: create pid record: %w", err)
	}
	_, werr := f.Write(append(body, '\n'))
	cerr := f.Close()
	if err := errors.Join(werr, cerr); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("confiner: write pid record %s: %w", path, err)
	}
	return nil
}

// replacePIDRecord atomically replaces the record at path, which the caller
// wrote with writePIDRecord and so owns: the new body goes to a temporary
// file beside it and is renamed into place, so a reader sees the old record
// or the new one, never a partial file. The temporary name starts with ".",
// which no reap prefix matches and no sweep lists as a record.
func replacePIDRecord(path string, r pidRecord) error {
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp")
	_ = os.Remove(tmp) // a leftover from a crash mid-replace; ours to reuse
	if err := writePIDRecord(tmp, r); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("confiner: replace pid record %s: %w", path, err)
	}
	return nil
}

// readPIDRecord reads a record written by writePIDRecord. A record that does
// not decode, or whose pid is 1 or negative, is an error: no compartment is
// ever pid 1 (launchd) or lower, and a signal to -pid for those values would
// reach the caller's own process group (0) or every process the user owns
// (1). Pid 0 is the PENDING record (see pidRecord) and decodes; every caller
// branches on it before it asks the kernel about a process, because pid 0 IS
// a kernel process whose start time a record must never be matched against.
// The caller treats an unreadable record as a compartment that is already
// gone.
func readPIDRecord(path string) (pidRecord, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return pidRecord{}, err
	}
	var r pidRecord
	if err := json.Unmarshal(body, &r); err != nil {
		return pidRecord{}, fmt.Errorf("confiner: pid record %s: %w", path, err)
	}
	if r.PID < 0 || r.PID == 1 {
		return pidRecord{}, fmt.Errorf("confiner: pid record %s: pid %d is not a process", path, r.PID)
	}
	return r, nil
}
