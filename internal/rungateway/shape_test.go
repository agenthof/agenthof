package rungateway

import (
	"os"
	"strings"
	"testing"
)

func packageSource(t *testing.T) string {
	t.Helper()
	var sb strings.Builder
	for _, f := range []string{"proxy.go", "exec.go", "spawn.go", "attestation.go", "errclass.go", "listen.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		sb.Write(b)
	}
	return sb.String()
}

// TestRouteDoorsRegisterThroughOneHelper pins by source that every route
// door joins the mux through registerDoor — the helper that takes the
// admission hold and counts — so a new door cannot be added around it
// unnoticed: the only mux.HandleFunc is the one inside the helper, the only
// mux.Handle is the MCP root.
func TestRouteDoorsRegisterThroughOneHelper(t *testing.T) {
	src := packageSource(t)
	if n := strings.Count(src, "mux.HandleFunc("); n != 1 {
		t.Fatalf("mux.HandleFunc( appears %d time(s); only registerDoor may call it", n)
	}
	if n := strings.Count(src, "mux.Handle("); n != 1 {
		t.Fatalf("mux.Handle( appears %d time(s); only the MCP root may use it", n)
	}
}

// TestEveryAppendSitsUnderTheAdmissionHold pins the one-hold invariant by
// source: the drop-on-closing appender is gone (the tool door's assertions
// — one inflight.Add, closing read only at admission — join once that door
// is converted).
func TestEveryAppendSitsUnderTheAdmissionHold(t *testing.T) {
	src := packageSource(t)
	if strings.Contains(src, "guardedAppend") {
		t.Fatal("guardedAppend must not exist: it drops a counted call's event once closing is set")
	}
}
