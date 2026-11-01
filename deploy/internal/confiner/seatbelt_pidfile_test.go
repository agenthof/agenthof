package confiner

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestPIDRecordRoundTripAndExclusive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "refexec-01.pid")
	want := pidRecord{PID: 4242, StartUnixMicro: 1761999999123456, Store: "w", OwnerPID: 77, OwnerStartUnixMicro: 1761999990000000}
	if err := writePIDRecord(path, want); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := readPIDRecord(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got != want {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode = %o, want 0600", perm)
	}

	// A second write to the same path must fail rather than replace a live
	// compartment's record.
	err = writePIDRecord(path, pidRecord{PID: 1, StartUnixMicro: 1, Store: "other"})
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("second write: err = %v, want fs.ErrExist", err)
	}
	if again, err := readPIDRecord(path); err != nil || again != want {
		t.Fatalf("record changed after a refused write: %+v, %v", again, err)
	}

	// Replacing is what completes a pending claim: the body changes in place,
	// the file keeps its mode, and the temporary file is gone.
	want.PID, want.StartUnixMicro = 4343, 1761999999999999
	if err := replacePIDRecord(path, want); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if got, err := readPIDRecord(path); err != nil || got != want {
		t.Fatalf("after replace = %+v, %v, want %+v", got, err, want)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode after replace: %v, %v", info, err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatalf("pid dir after replace: %v, %v (want only the record)", entries, err)
	}
}

// A record written before the owner fields existed decodes, as owned by
// nobody; a pending one (pid 0, the claim before the process) decodes too.
func TestReadPIDRecordAcceptsOldAndPendingRecords(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "old.pid")
	if err := os.WriteFile(old, []byte(`{"pid":4242,"start_unix_micro":7,"store":"w"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec, err := readPIDRecord(old)
	if err != nil || rec != (pidRecord{PID: 4242, StartUnixMicro: 7, Store: "w"}) {
		t.Fatalf("old record = %+v, %v", rec, err)
	}
	if rec.owner() != (ownerRef{}) {
		t.Fatalf("an unstamped record has owner %+v, want none", rec.owner())
	}
	pending := filepath.Join(dir, "pending.pid")
	if err := writePIDRecord(pending, pidRecord{Store: "w", OwnerPID: 77, OwnerStartUnixMicro: 8}); err != nil {
		t.Fatal(err)
	}
	rec, err = readPIDRecord(pending)
	if err != nil || rec.PID != 0 || rec.owner() != (ownerRef{pid: 77, start: 8}) {
		t.Fatalf("pending record = %+v, %v", rec, err)
	}
}

func TestReadPIDRecordRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"empty":   "",
		"notjson": "pid 12",
		"pid-1":   `{"pid":1,"start_unix_micro":1,"store":"w"}`,
		"neg-pid": `{"pid":-5,"start_unix_micro":1,"store":"w"}`,
	} {
		p := filepath.Join(dir, name+".pid")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readPIDRecord(p); err == nil {
			t.Errorf("%s: read %q without error", name, body)
		}
	}
	if _, err := readPIDRecord(filepath.Join(dir, "missing.pid")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing: err = %v, want fs.ErrNotExist", err)
	}
}
