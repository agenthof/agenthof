package confiner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// hardLinkUnsupported names a filesystem-without-hard-links failure so a launch
// fails clearly; a taken name (fs.ErrExist) is the exclusive-claim refusal, not
// a missing-hard-links error, and any other errno leaves the launch's own error.
func TestHardLinkUnsupportedClassifiesErrors(t *testing.T) {
	for _, no := range []error{syscall.EPERM, syscall.EOPNOTSUPP, syscall.ENOTSUP, syscall.EXDEV} {
		if !hardLinkUnsupported(fmt.Errorf("link: %w", no)) {
			t.Errorf("%v: not classified as no-hard-links", no)
		}
	}
	for name, err := range map[string]error{
		"taken name": fs.ErrExist,
		"not exist":  fs.ErrNotExist,
		"plain":      errors.New("io"),
	} {
		if hardLinkUnsupported(err) {
			t.Errorf("%s (%v): classified as no-hard-links", name, err)
		}
	}
}

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

// A name that already has a record is refused, never replaced — and the
// refusal is fs.ErrExist to a caller, whatever path the write takes.
func TestWritePIDRecordExclusiveClaimPreserved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "refexec-01.pid")
	want := pidRecord{Store: "w", OwnerPID: 77, OwnerStartUnixMicro: 8}
	if err := writePIDRecord(path, want); err != nil {
		t.Fatal(err)
	}
	err := writePIDRecord(path, pidRecord{PID: 9, StartUnixMicro: 9, Store: "other"})
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("second write: err = %v, want fs.ErrExist", err)
	}
	if got, err := readPIDRecord(path); err != nil || got != want {
		t.Fatalf("record after a refused write = %+v, %v, want %+v", got, err, want)
	}
}

// The claim is published through a temporary file beside the record; after a
// success and after a refused write alike, only the record itself remains.
func TestWritePIDRecordLeavesNoTempOnSuccessOrCollision(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "refexec-01.pid")
	if err := writePIDRecord(path, pidRecord{Store: "w", OwnerPID: 77}); err != nil {
		t.Fatal(err)
	}
	onlyTheRecord := func(when string) {
		t.Helper()
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
			var names []string
			for _, e := range entries {
				names = append(names, e.Name())
			}
			t.Fatalf("%s: pid dir holds %v, want only %s", when, names, filepath.Base(path))
		}
	}
	onlyTheRecord("after the claim")
	if err := writePIDRecord(path, pidRecord{Store: "other"}); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("second write: err = %v, want fs.ErrExist", err)
	}
	onlyTheRecord("after a refused claim")
}

// What a reader finds at the path is the whole record: the exact fields, the
// trailing newline, mode 0600.
func TestWritePIDRecordPublishesCompleteRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "refexec-01.pid")
	want := pidRecord{PID: 4242, StartUnixMicro: 1761999999123456, Store: "w", OwnerPID: 77, OwnerStartUnixMicro: 1761999990000000}
	if err := writePIDRecord(path, want); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) == 0 || body[len(body)-1] != '\n' {
		t.Fatalf("record body %q does not end in a newline", body)
	}
	var got pidRecord
	if err := json.Unmarshal(body, &got); err != nil || got != want {
		t.Fatalf("published record = %+v, %v, want %+v", got, err, want)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, %v, want 0600", info, err)
	}
}

// A concurrent reader never sees the record half-written: the name appears
// only once the body is complete. The claim exists so a sibling's Reap, which
// may list the pid dir at any moment, sees a name a running instance owns; a
// reader that found an empty file would take the record for unreadable and
// remove the compartment's scratch dir from under it. Best-effort: the reader
// polls, so a window it never happens to hit passes; a non-empty partial it
// does hit fails.
func TestWritePIDRecordNeverObservedPartial(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "refexec-01.pid")
	rec := pidRecord{Store: "w", OwnerPID: 77, OwnerStartUnixMicro: 1761999990000000}
	stop := make(chan struct{})
	partial := make(chan []byte, 1)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			body, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			var r pidRecord
			if json.Unmarshal(body, &r) != nil || r != rec {
				select {
				case partial <- body:
				default:
				}
				return
			}
		}
	}()
	for i := 0; i < 300; i++ {
		if err := writePIDRecord(path, rec); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		select {
		case body := <-partial:
			t.Fatalf("a reader saw a partial record: %q", body)
		default:
		}
	}
	close(stop)
	select {
	case body := <-partial:
		t.Fatalf("a reader saw a partial record: %q", body)
	default:
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
