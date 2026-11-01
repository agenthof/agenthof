package confiner

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// pidRecord is what the Seatbelt backend keeps per live compartment, so a
// later process (RemoveStore, Reap) can tell the SAME process from a reused
// pid: the pid alone is never trusted, its start time must match too.
type pidRecord struct {
	PID            int    `json:"pid"`
	StartUnixMicro int64  `json:"start_unix_micro"`
	Store          string `json:"store"`
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

// readPIDRecord reads a record written by writePIDRecord. A record that does
// not decode, or that names a non-positive pid (which no live compartment has,
// and which a signal to -pid would turn into the caller's own process group),
// is an error; the caller treats an unreadable record as a compartment that is
// already gone.
func readPIDRecord(path string) (pidRecord, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return pidRecord{}, err
	}
	var r pidRecord
	if err := json.Unmarshal(body, &r); err != nil {
		return pidRecord{}, fmt.Errorf("confiner: pid record %s: %w", path, err)
	}
	if r.PID <= 0 {
		return pidRecord{}, fmt.Errorf("confiner: pid record %s: pid %d is not a process", path, r.PID)
	}
	return r, nil
}
