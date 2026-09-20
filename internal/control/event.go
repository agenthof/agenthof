// Package control implements the control/1 event type and a writer that
// appends control-plane events (apply, enable/disable, repair, ...) to a
// Locked, hash-chained ledger (internal/ledger). Every control record
// carries a contiguous "seq" from 1, distinguishing a control log from a
// run log (which never carries seq) per the ledger's seq-mode rule.
package control

import (
	"os"
	"os/user"

	"github.com/agenthof/agenthof/internal/identity"
)

// Reason codes for a control/1 record whose outcome is not "success".
const (
	CodeValidationFailed        = "validation_failed"
	CodeTokenVerificationFailed = "token_verification_failed"
	CodeLedgerDamaged           = "ledger_damaged"
	CodeAgentNotFound           = "agent_not_found"
	CodeIOError                 = "io_error"
)

// Reason explains a non-success outcome.
type Reason struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Witness records the local OS user and hostname that produced a control
// record, independent of the asserted Invoker identity.
type Witness struct {
	OSUser   string `json:"os_user"`
	Hostname string `json:"hostname"`
}

// Event is a control/1 record. Callers set Action, Agent, Outcome, Reason,
// Invoker, AssertedAs, Witness, ConfigHash, and (repair only) FragmentLen/
// FragmentSHA. V, and the seq/time/prev/log_id fields on the wire, are set
// by Append; callers never set them.
type Event struct {
	V           string           `json:"v,omitempty"`
	Action      string           `json:"action"`
	Agent       string           `json:"agent,omitempty"`
	Outcome     string           `json:"outcome"`
	Reason      *Reason          `json:"reason,omitempty"`
	Invoker     identity.Invoker `json:"invoker"`
	AssertedAs  string           `json:"asserted_as,omitempty"`
	Witness     Witness          `json:"witness"`
	ConfigHash  string           `json:"config_hash,omitempty"`
	FragmentLen int              `json:"fragment_len,omitempty"`
	FragmentSHA string           `json:"fragment_sha256,omitempty"`
}

// CaptureWitness captures the local OS user (preferring $USER, falling
// back to os/user.Current) and hostname for a Witness.
func CaptureWitness() Witness {
	u := os.Getenv("USER")
	if u == "" {
		if cur, err := user.Current(); err == nil {
			u = cur.Username
		}
	}
	host, _ := os.Hostname()
	return Witness{OSUser: u, Hostname: host}
}
