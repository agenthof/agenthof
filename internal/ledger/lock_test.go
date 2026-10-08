package ledger

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestMain implements the multi-process helper pattern. With
// LEDGER_HELPER_PATH set, this binary opens the ledger Locked, appends
// LEDGER_HELPER_N lines one at a time (closing and reopening the Chain
// between appends so each Open must re-acquire the lock), and exits. With
// LEDGER_LOCKFILE_HOLD set, it takes LockFile on that path, prints "held",
// holds it for LEDGER_LOCKFILE_HOLD_MS milliseconds, releases, and exits.
func TestMain(m *testing.M) {
	if p := os.Getenv("LEDGER_HELPER_PATH"); p != "" {
		n, _ := strconv.Atoi(os.Getenv("LEDGER_HELPER_N"))
		for i := 0; i < n; i++ {
			c, err := Open(p, Locked)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			line, _ := json.Marshal(map[string]any{"prev": c.Prev(), "pid": os.Getpid(), "i": i})
			if err := c.Append(line); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			_ = c.Close()
		}
		os.Exit(0)
	}
	if p := os.Getenv("LEDGER_LOCKFILE_HOLD"); p != "" {
		unlock, err := LockFile(p)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("held")
		ms, _ := strconv.Atoi(os.Getenv("LEDGER_LOCKFILE_HOLD_MS"))
		time.Sleep(time.Duration(ms) * time.Millisecond)
		unlock()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// TestLockedOpenContendsAndTimesOut verifies that a second Locked Open on
// the same file, while the first holder still has it open, blocks and then
// gives up with the pinned error message once lockTimeout elapses.
func TestLockedOpenContendsAndTimesOut(t *testing.T) {
	orig := lockTimeout
	lockTimeout = 200 * time.Millisecond
	defer func() { lockTimeout = orig }()

	p := filepath.Join(t.TempDir(), "chain.jsonl")
	c1, err := Open(p, Locked)
	if err != nil {
		t.Fatalf("first Open(Locked): %v", err)
	}
	defer func() { _ = c1.Close() }()

	start := time.Now()
	_, err = Open(p, Locked)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("second Open(Locked) should have failed while first holder is open")
	}
	if !strings.Contains(err.Error(), "another agenthof process holds the ledger lock") {
		t.Fatalf("wrong error message: %v", err)
	}
	if elapsed < lockTimeout {
		t.Fatalf("returned too early: %v < %v", elapsed, lockTimeout)
	}
}

// TestLockedReadVerifyBlocksThenSucceeds verifies that ReadVerify(path,
// Locked) blocks while a writer holds the exclusive lock, and succeeds
// once that writer closes.
func TestLockedReadVerifyBlocksThenSucceeds(t *testing.T) {
	p := filepath.Join(t.TempDir(), "chain.jsonl")
	writer, err := Open(p, Locked)
	if err != nil {
		t.Fatalf("Open(Locked): %v", err)
	}
	line := mkLine(t, writer.Prev(), "a")
	if err := writer.Append(line); err != nil {
		t.Fatalf("Append: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		time.Sleep(150 * time.Millisecond)
		_ = writer.Close()
	}()

	start := time.Now()
	recs, head, err := ReadVerify(p, Locked)
	elapsed := time.Since(start)
	<-done
	if err != nil {
		t.Fatalf("ReadVerify(Locked) after writer closed: %v", err)
	}
	if len(recs) != 1 || head.Count != 1 {
		t.Fatalf("bad result: %d records, head %+v", len(recs), head)
	}
	if elapsed < 100*time.Millisecond {
		t.Fatalf("ReadVerify returned suspiciously fast (%v): did it actually block on the lock?", elapsed)
	}
}

// TestMultiProcessAppend is the real proof: several real OS processes race
// to append to the same ledger file under Locked mode. If locking works,
// every append lands, none are lost, and the chain verifies clean.
func TestMultiProcessAppend(t *testing.T) {
	p := filepath.Join(t.TempDir(), "chain.jsonl")
	const procs, per = 4, 25
	var wg sync.WaitGroup
	errs := make(chan error, procs)
	for i := 0; i < procs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cmd := exec.Command(os.Args[0], "-test.run=TestMultiProcessAppend")
			cmd.Env = append(os.Environ(), "LEDGER_HELPER_PATH="+p, "LEDGER_HELPER_N="+strconv.Itoa(per))
			if out, err := cmd.CombinedOutput(); err != nil {
				errs <- fmt.Errorf("%v: %s", err, out)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	recs, head, err := ReadVerify(p, Locked)
	if err != nil {
		t.Fatalf("verify after contention: %v", err)
	}
	if len(recs) != procs*per || head.Count != procs*per {
		t.Fatalf("lost or forked appends: %d", len(recs))
	}
}

// TestLockFileContendsInProcessAndTimesOut: flock is per open file
// description, so two LockFile calls in ONE process contend exactly like
// two processes; the loser gets an error satisfying errors.Is(err,
// ErrLockHeld) after lockTimeout, and the file (and its directory) is
// created on first use.
func TestLockFileContendsInProcessAndTimesOut(t *testing.T) {
	orig := lockTimeout
	lockTimeout = 200 * time.Millisecond
	defer func() { lockTimeout = orig }()

	p := filepath.Join(t.TempDir(), "sub", "installed.lock")
	unlock, err := LockFile(p)
	if err != nil {
		t.Fatalf("first LockFile: %v", err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("lock file must exist: %v", err)
	}
	start := time.Now()
	_, err = LockFile(p)
	if !errors.Is(err, ErrLockHeld) {
		t.Fatalf("second LockFile err = %v, want ErrLockHeld", err)
	}
	if elapsed := time.Since(start); elapsed < lockTimeout {
		t.Fatalf("returned too early: %v < %v", elapsed, lockTimeout)
	}
	unlock()
	unlock2, err := LockFile(p)
	if err != nil {
		t.Fatalf("after unlock, LockFile must succeed: %v", err)
	}
	unlock2()
}

// TestLockFileCrossProcess: a real OS process holding the lock makes the
// parent time out; once it exits the lock is free.
func TestLockFileCrossProcess(t *testing.T) {
	orig := lockTimeout
	lockTimeout = 200 * time.Millisecond
	defer func() { lockTimeout = orig }()

	p := filepath.Join(t.TempDir(), "installed.lock")
	cmd := exec.Command(os.Args[0], "-test.run=TestLockFileCrossProcess")
	cmd.Env = append(os.Environ(), "LEDGER_LOCKFILE_HOLD="+p, "LEDGER_LOCKFILE_HOLD_MS=1500")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	var line [5]byte
	if _, err := io.ReadFull(stdout, line[:]); err != nil || string(line[:]) != "held\n" {
		t.Fatalf("helper never reported the lock held: %q err=%v", line[:], err)
	}
	if _, err := LockFile(p); !errors.Is(err, ErrLockHeld) {
		t.Fatalf("LockFile while the helper holds it: err = %v, want ErrLockHeld", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("helper: %v", err)
	}
	unlock, err := LockFile(p)
	if err != nil {
		t.Fatalf("after the helper exited: %v", err)
	}
	unlock()
}

// TestOpenWrapsErrLockHeld: Open's contention error is still the pinned
// message AND satisfies errors.Is against the exported value, so callers can
// tell contention from damage.
func TestOpenWrapsErrLockHeld(t *testing.T) {
	orig := lockTimeout
	lockTimeout = 100 * time.Millisecond
	defer func() { lockTimeout = orig }()
	p := filepath.Join(t.TempDir(), "chain.jsonl")
	c1, err := Open(p, Locked)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c1.Close() }()
	_, err = Open(p, Locked)
	if !errors.Is(err, ErrLockHeld) {
		t.Fatalf("Open contention err = %v, want ErrLockHeld", err)
	}
}
