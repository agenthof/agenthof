package control_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/sidecar"
)

// TestRunIDShapeAgreesWithSidecar pins control's own run-id shape (it cannot
// import internal/sidecar) to sidecar.RunIDRE: the permit accepts exactly the
// ids the sidecar's file name is built from.
func TestRunIDShapeAgreesWithSidecar(t *testing.T) {
	p, inv, w := appliedLedger(t)
	for _, id := range []string{
		"r-0123456789abcdef",
		"r-0123456789ABCDEF",
		"r-0123",
		"r-0123456789abcdef0",
		"../x",
		"x-0123456789abcdef",
	} {
		a := goodAnchor()
		a.RunID, a.Proof = id, ""
		_, err := control.Append(p, control.Event{Action: "anchor", Outcome: "success", Invoker: inv, Witness: w, Anchor: a})
		accepted := err == nil
		if want := sidecar.RunIDRE.MatchString(id); accepted != want {
			t.Fatalf("%q: control accepts=%v (%v), sidecar.RunIDRE matches=%v", id, accepted, err, want)
		}
		if err != nil && !strings.HasPrefix(err.Error(), fmt.Sprintf("control: anchor run_id %q", id)) {
			t.Fatalf("%q: unexpected refusal %v", id, err)
		}
	}
}
