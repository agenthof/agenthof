package control_test

import (
	"testing"

	"github.com/agenthof/agenthof/internal/control"
)

// TestNotAuthorizedReasonIsFixed: the recorded message names the operation
// and nothing else — never the invoker's groups, which under --groups are
// self-asserted and under a token are claims the ledger must not echo.
func TestNotAuthorizedReasonIsFixed(t *testing.T) {
	r := control.NotAuthorized("apply")
	if r.Code != control.CodeNotAuthorized || control.CodeNotAuthorized != "not_authorized" {
		t.Fatalf("code = %q", r.Code)
	}
	if r.Message != "not authorized: no role grants apply to the invoker" {
		t.Fatalf("message = %q", r.Message)
	}
}
