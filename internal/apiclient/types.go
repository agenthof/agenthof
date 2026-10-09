// Package apiclient is the wire contract of the agenthof serve API and the
// thin client the CLI uses to speak it. The Go types here ARE the
// contract: internal/serve encodes them and this client decodes them, so a
// field added on one side is visible to the other at compile time, and
// the round-trip tests pin the JSON keys. Additive only (Article VI): new
// fields are omitempty, nothing is renamed.
package apiclient

import (
	"net/url"
	"time"

	"github.com/agenthof/agenthof/internal/engine"
)

// RunRequest is the body of POST /v1/runs.
type RunRequest struct {
	Role     string `json:"role"`
	Workflow string `json:"workflow"`
	Input    string `json:"input"`
}

// Run statuses beyond engine.Result.Status: a run in flight, and a run
// whose ledger has no terminal event (the process ended before it did).
const (
	StatusRunning    = "running"
	StatusIncomplete = "incomplete"
	StatusRefused    = "refused"
)

// RunAccepted answers POST /v1/runs: 202 with StatusRunning, or 403/422
// with StatusRefused and the reason the client prints.
type RunAccepted struct {
	RunID  string `json:"run_id"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// RunStatus answers GET /v1/runs/{id}. Status is engine.Result.Status or
// StatusRunning/StatusIncomplete. OutputSHA/OutputPreview are set only on
// a succeeded run — the artifact body never travels (Article III).
type RunStatus struct {
	RunID         string     `json:"run_id"`
	Status        string     `json:"status"`
	Reason        string     `json:"reason,omitempty"`
	Started       time.Time  `json:"started"`
	Finished      *time.Time `json:"finished,omitempty"`
	OutputSHA     string     `json:"output_sha,omitempty"`
	OutputPreview string     `json:"output_preview,omitempty"`
}

// RunSummary is one row of GET /v1/runs.
type RunSummary struct {
	RunID  string `json:"run_id"`
	Status string `json:"status"`
}

// RunList answers GET /v1/runs: the hosted runs and every run log on disk.
type RunList struct {
	Runs []RunSummary `json:"runs"`
}

// Head is a ledger head: the hash of the last verified record and how
// many records that prefix holds.
type Head struct {
	Hash  string `json:"hash"`
	Count int    `json:"count"`
}

// Integrity verdicts for a run ledger as the API reads it. IntegrityInFlight
// is a torn tail on a run this process is still writing — a record caught
// mid-write, not damage; it becomes torn or verified once the run ends.
const (
	IntegrityVerified = "verified"
	IntegrityInFlight = "in_flight"
	IntegrityTorn     = "torn"
	IntegrityBroken   = "broken"
)

// RunEvents answers GET /v1/runs/{id}/events: the verified prefix, its
// head, the verdict, and — when broken — the 1-based line that broke it.
type RunEvents struct {
	Events     []engine.Event `json:"events"`
	Head       Head           `json:"head"`
	Integrity  string         `json:"integrity"`
	BrokenLine int            `json:"broken_line,omitempty"`
}

// IntegrityHeader carries GET /v1/runs/{id}/audit's verdict beside its
// text body, so a client can exit the way the local audit command does.
const IntegrityHeader = "Agenthof-Integrity"

// InvestigateQuery is GET /v1/investigate's query string. Since and Until
// are RFC3339; a client resolves durations before sending.
type InvestigateQuery struct {
	Since, Until, Invoker, Agent, Outcome, Run, ConfigHash string
}

// Values encodes q, omitting empty fields.
func (q InvestigateQuery) Values() url.Values {
	v := url.Values{}
	for k, s := range map[string]string{
		"since": q.Since, "until": q.Until, "invoker": q.Invoker, "agent": q.Agent,
		"outcome": q.Outcome, "run": q.Run, "config_hash": q.ConfigHash,
	} {
		if s != "" {
			v.Set(k, s)
		}
	}
	return v
}

// InvestigateQueryFrom decodes v; unknown parameters are ignored.
func InvestigateQueryFrom(v url.Values) InvestigateQuery {
	return InvestigateQuery{
		Since: v.Get("since"), Until: v.Get("until"), Invoker: v.Get("invoker"), Agent: v.Get("agent"),
		Outcome: v.Get("outcome"), Run: v.Get("run"), ConfigHash: v.Get("config_hash"),
	}
}

// MaxApplyBody caps POST /v1/config/apply's body (1 MiB — the same value
// as the run body, a separate constant because it is a separate contract);
// MaxBundleFiles caps the entries in a bundle. The server enforces both;
// the CLI client checks them before sending.
const (
	MaxApplyBody   = 1 << 20
	MaxBundleFiles = 1000
)

// ApplyRequest is the body of POST /v1/config/apply: the configuration's
// files by their config-relative path (agents/, workflows/, roles/,
// gateway.yaml), as text. It is also the `apply --bundle` file format.
type ApplyRequest struct {
	Files map[string]string `json:"files"`
}

// Precondition is the client's declared view of the installed
// configuration: If-Match: sha256:<hex> (ExpectInstalled) or If-None-Match:
// * (ExpectNone — install only if nothing is installed). Exactly one is
// always sent; an apply with no precondition is not offered over the API.
type Precondition struct {
	ExpectInstalled string
	ExpectNone      bool
}

// ApplyResult answers POST /v1/config/apply. Status is one of the Apply*
// constants; the HTTP code follows from it.
type ApplyResult struct {
	Status      string   `json:"status"`
	ConfigHash  string   `json:"config_hash,omitempty"`  // installed / rejected / refused / installed_not_recorded / installed_not_signed
	CurrentHash string   `json:"current_hash,omitempty"` // precondition_failed, when something is installed
	Bootstrap   bool     `json:"bootstrap,omitempty"`    // installed: nothing was installed before
	Reason      string   `json:"reason,omitempty"`       // refused / rejected / error: the recorded reason message
	Errors      []string `json:"errors,omitempty"`       // rejected: every load and validation error, as apply prints them
	Head        *Head    `json:"head,omitempty"`         // the control head after the recorded event
	Agents      int      `json:"agents,omitempty"`
	Workflows   int      `json:"workflows,omitempty"`
	Roles       int      `json:"roles,omitempty"`
	KeyID       string   `json:"key_id,omitempty"` // installed: the operator's signing key id, when the server signs
}

// Apply statuses.
const (
	ApplyInstalled            = "installed"
	ApplyRefused              = "refused"
	ApplyRejected             = "rejected"
	ApplyPreconditionFailed   = "precondition_failed"
	ApplyError                = "error"
	ApplyLedgerDamaged        = "ledger_damaged"
	ApplyBusy                 = "busy"
	ApplyInstalledNotRecorded = "installed_not_recorded"
	ApplyInstalledNotSigned   = "installed_not_signed"
)

// Fixed reasons on a 500 answer: the server never returns the recorded OS
// text (it can name store paths); the operator who has the host reads it in
// the control ledger and the server log.
const (
	ReasonStoreUnusable = "store unusable"
	ReasonLedgerDamaged = "control ledger damaged"
	ReasonNotRecorded   = "control event could not be recorded"
)

// ConfigSnapshot answers GET /v1/config (with Files) and GET /v1/config/hash
// (without). Hash is the installed pointer; Version is the control-ledger
// sequence number of the event that installed it (an apply, or a kill-switch
// flip against an installed snapshot) and InstalledAt that event's time;
// Files is the configuration by config-relative path, the exact body
// POST /v1/config/apply accepts. A 200 always carries all three of Hash,
// Version and InstalledAt — the server answers 503 rather than a snapshot
// the ledger does not vouch for — and on GET /v1/config Files is never
// empty (every installed snapshot passed the no-apply-floor, so it holds
// at least one roles file); omitempty exists only for the hash route.
// Additive (Article VI): a signature over the files/v1 canon is reserved
// as a further field named "signature"; no consumer may use that name for
// anything else.
type ConfigSnapshot struct {
	Hash        string            `json:"hash"`
	Version     int               `json:"version"`
	InstalledAt time.Time         `json:"installed_at"`
	Files       map[string]string `json:"files,omitempty"`
}

// Fixed text bodies on the configuration pull's non-200 answers. The
// server writes them with http.Error and the local pull prints the same
// words, so one condition reads the same from either side. The 404 body is
// serve.ErrNoConfigInstalled's text; the 500 store and ledger bodies are
// ReasonStoreUnusable and ReasonLedgerDamaged.
const (
	PullBodyRefused       = "not authorized: no role grants pull or apply to the invoker"
	PullBodyNotBundleable = "snapshot cannot be distributed as a bundle"
	PullBodyNotRecorded   = "installed configuration is not yet on record; retry"
	PullBodyBusy          = "control ledger busy; retry"
)
