package engine

import (
	"fmt"
	"sync"
	"testing"
)

// TestLogAppendConcurrent proves Log.Append is safe for concurrent callers:
// the engine and the run gateway append to the same hash-chained log from
// different goroutines. Run with -race.
func TestLogAppendConcurrent(t *testing.T) {
	dir := t.TempDir()
	log, err := OpenLog(dir, "r-concurrent")
	if err != nil {
		t.Fatalf("OpenLog: %v", err)
	}

	const n = 50
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- log.Append(Event{Type: "tool_call", Agent: fmt.Sprintf("a%d", i)})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Append: %v", err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	events, _, err := ReadLog(dir, "r-concurrent")
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}
	if len(events) != n {
		t.Fatalf("got %d events, want %d (appends lost or chain torn)", len(events), n)
	}
}
