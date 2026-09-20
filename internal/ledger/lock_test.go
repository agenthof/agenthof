package ledger

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestMain implements the multi-process helper pattern: when invoked with
// LEDGER_HELPER_PATH set, this binary acts as a helper process that opens
// the ledger Locked, appends LEDGER_HELPER_N lines one at a time (closing
// and reopening the Chain between appends so each Open must re-acquire the
// lock), and exits — rather than running the normal test suite.
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
			c.Close()
		}
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
	defer c1.Close()

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
		writer.Close()
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
