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
	want := pidRecord{PID: 4242, StartUnixMicro: 1761999999123456, Store: "w"}
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
}

func TestReadPIDRecordRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"empty":    "",
		"notjson":  "pid 12",
		"zero-pid": `{"pid":0,"start_unix_micro":1,"store":"w"}`,
		"neg-pid":  `{"pid":-5,"start_unix_micro":1,"store":"w"}`,
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
