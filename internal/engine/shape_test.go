package engine

import (
	"os"
	"strings"
	"testing"
)

// TestStepTerminalsOnlyFromFinishStep pins by source that the two step
// terminals are built in exactly one place — the helper that stamps
// door_calls — so no emission site can forget the count.
func TestStepTerminalsOnlyFromFinishStep(t *testing.T) {
	src, err := os.ReadFile("engine.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, lit := range []string{`"step_succeeded"`, `"step_failed"`} {
		if n := strings.Count(string(src), lit); n != 1 {
			t.Fatalf("engine.go names %s %d time(s); it must appear exactly once, inside finishStep", lit, n)
		}
	}
}
