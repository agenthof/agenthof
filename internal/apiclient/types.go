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
