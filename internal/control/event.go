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
	"github.com/agenthof/agenthof/internal/origin"
)

// Reason codes for a control/1 record whose outcome is not "success".
const (
	CodeValidationFailed        = "validation_failed"
	CodeTokenVerificationFailed = "token_verification_failed"
	CodeLedgerDamaged           = "ledger_damaged"
	CodeAgentNotFound           = "agent_not_found"
	CodeIOError                 = "io_error"
	CodeNotAuthorized           = "not_authorized"
)

// Reason explains a non-success outcome.
type Reason struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// NotAuthorized is the reason for a control action no role grants the
// invoker (authz.ControlAllows said no). The message is fixed and
// self-describing: it names the operation, never the invoker's groups.
func NotAuthorized(op string) *Reason {
	return &Reason{Code: CodeNotAuthorized, Message: "not authorized: no role grants " + op + " to the invoker"}
}

// Witness records the local OS user and hostname that produced a control
// record, independent of the asserted Invoker identity.
type Witness struct {
	OSUser   string `json:"os_user"`
	Hostname string `json:"hostname"`
}

// Event is a control/1 record. Callers set Action, Agent, Outcome, Reason,
// Invoker, AssertedAs, Witness, ConfigHash, Bootstrap (apply and
// enable/disable), Origin (an API-recorded action; nil from the CLI),
// Detail (runs prune only), and (repair only) FragmentLen/FragmentSHA. V,
// and the seq/time/prev/log_id fields on the wire, are set by Append;
// callers never set them.
type Event struct {
	V          string           `json:"v,omitempty"`
	Action     string           `json:"action"`
	Agent      string           `json:"agent,omitempty"`
	Outcome    string           `json:"outcome"`
	Reason     *Reason          `json:"reason,omitempty"`
	Invoker    identity.Invoker `json:"invoker"`
	AssertedAs string           `json:"asserted_as,omitempty"`
	Witness    Witness          `json:"witness"`
	ConfigHash string           `json:"config_hash,omitempty"`
	// Bootstrap marks a successful apply or kill-switch flip that ran while
	// nothing was installed under its control root. An apply so marked
	// installed the first snapshot (or the first after an operator removed
	// the installed pointer); a flip so marked edited the configuration
	// directory, recorded that directory's hash, and installed nothing — the
	// audit readers exclude it from "what is installed" (see Installing).
	// Additive: absent on every other record, omitted from the wire when
	// false.
	Bootstrap   bool   `json:"bootstrap,omitempty"`
	FragmentLen int    `json:"fragment_len,omitempty"`
	FragmentSHA string `json:"fragment_sha256,omitempty"`
	// Origin is where the action's request arrived from — set by serve on
	// an API-recorded action, nil from the CLI. Provenance from the
	// untrusted request channel, never a witness: the witness on an API
	// record is the serving host's OS user and hostname. Sanitized by
	// Append. Additive and omitempty (Article VI): absent on every record
	// written before it existed and on every CLI record after.
	Origin *origin.Origin `json:"origin,omitempty"`
	// Detail is a short human-readable summary of what a successful or
	// partially-successful action did, for the audit reader — "pruned 3 run(s)
	// and 1 artifact(s) older than 180d". It is forensic prose, not a join key:
	// nothing decides anything from it, and no reader parses it. Set by runs
	// prune; empty on every other record. Sanitized by Append (origin.Clean:
	// printable runes only, at most 200). Additive and omitempty (Article VI):
	// absent on every record written before it existed and on every record
	// that does not set it.
	Detail string `json:"detail,omitempty"`
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
