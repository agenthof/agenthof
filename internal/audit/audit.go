package audit

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/ledger"
)

// integrityLine renders the "ledger integrity: ..." line shared by both the
// normal and the no-decodable-events render paths. verr is nil for a clean
// ledger, or the typed ledger error (*ledger.TornError /
// *ledger.ChainBrokenError) describing where verification stopped. head is
// the verified prefix's Head — Count is used rather than len(events) so the
// count stays correct even when Render is invoked with a nil/short events
// slice (e.g. an open/IO failure path with no decoded events at all).
func integrityLine(head ledger.Head, verr error) string {
	if verr == nil {
		return fmt.Sprintf("ledger integrity: verified (%d events)\n", head.Count)
	}
	if broken, ok := errors.AsType[*ledger.ChainBrokenError](verr); ok {
		return fmt.Sprintf("ledger integrity: BROKEN at event %d\n", broken.Line-1)
	}
	// A torn ledger has no repair hint here: that hint only makes sense for
	// the control ledger (E2), which can be regenerated; a run's event log
	// has no such recovery path, so the banner just names the failure.
	if _, ok := errors.AsType[*ledger.TornError](verr); ok {
		return "ledger integrity: TORN — last record incomplete\n"
	}
	return "ledger integrity: BROKEN at event 0\n"
}

// Render renders the given events (the valid prefix of a run's ledger) as
// a human-readable audit trail. head and verr are ReadLog's second and
// third return values.
//
// A torn/broken ledger can leave zero decodable events (e.g. the ledger
// crashed right after its very first, now-incomplete, write) — that must
// still surface the integrity failure rather than being mistaken for a
// genuinely empty run, so the verr check runs before the empty-events
// short-circuit.
func Render(events []engine.Event, head ledger.Head, verr error) string {
	if len(events) == 0 {
		if verr != nil {
			return integrityLine(head, verr)
		}
		return "no events for this run\n"
	}
	b := events[0].Binding
	status := "incomplete"
	for _, e := range events {
		if e.Type == "workflow_finished" {
			status = e.Status
		}
		if e.Type == "run_refused" {
			status = "refused"
		}
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "run %s — %s (role %s)\n", b.RunID, b.Workflow, b.Role)
	fmt.Fprintf(&sb, "invoked by %s (%s, issuer %s)\n", b.Invoker.Subject, b.Invoker.Method, b.Invoker.Issuer)
	fmt.Fprintf(&sb, "status: %s\n", status)
	sb.WriteString(integrityLine(head, verr))
	fmt.Fprint(&sb, "\n")
	for _, e := range events {
		t := e.Time.UTC().Format("15:04:05")
		switch e.Type {
		case "workflow_started":
			fmt.Fprintf(&sb, "  %s  workflow started\n", t)
		case "step_started":
			fmt.Fprintf(&sb, "  %s  step %s (agent %s) started\n", t, e.Step, e.Agent)
		case "step_succeeded":
			sha := e.ArtifactSHA
			if sha == "" {
				sha = "-"
			} else if len(sha) > 8 {
				sha = sha[:8]
			}
			fmt.Fprintf(&sb, "  %s  step %s succeeded — artifact %s: %s\n", t, e.Step, sha, e.Artifact)
		case "step_failed":
			fmt.Fprintf(&sb, "  %s  step %s (agent %s) failed — %s\n", t, e.Step, e.Agent, e.Reason)
		case "bounced_back":
			fmt.Fprintf(&sb, "  %s  bounced back to %s\n", t, e.Status)
		case "workflow_finished":
			fmt.Fprintf(&sb, "  %s  workflow finished: %s\n", t, e.Status)
		case "run_refused":
			fmt.Fprintf(&sb, "  %s  run refused — %s\n", t, e.Reason)
		case "exec":
			if e.Status == "refused" {
				fmt.Fprintf(&sb, "  %s  exec %s refused — %s\n", t, strings.Join(e.Command, " "), e.Reason)
			} else {
				exit := "?"
				if e.ExitCode != nil {
					exit = strconv.Itoa(*e.ExitCode)
				}
				fmt.Fprintf(&sb, "  %s  exec %s — exit %s (%s)\n", t, strings.Join(e.Command, " "), exit, e.Mode)
			}
		case "model_call":
			switch e.Status {
			case "refused", "failed":
				fmt.Fprintf(&sb, "  %s  model %s %s — %s\n", t, e.Model, e.Status, e.Reason)
			case "started":
				fmt.Fprintf(&sb, "  %s  model %s — streaming (usage not captured)\n", t, e.Model)
			case "succeeded":
				pt, ct := "?", "?"
				if e.PromptTokens != nil {
					pt = strconv.Itoa(*e.PromptTokens)
				}
				if e.CompletionTokens != nil {
					ct = strconv.Itoa(*e.CompletionTokens)
				}
				fmt.Fprintf(&sb, "  %s  model %s — %s prompt / %s completion tokens\n", t, e.Model, pt, ct)
			default:
				fmt.Fprintf(&sb, "  %s  model %s %s\n", t, e.Model, e.Status)
			}
		case "tool_call":
			switch e.Status {
			case "refused", "failed":
				fmt.Fprintf(&sb, "  %s  tool %s %s — %s\n", t, e.Tool, e.Status, e.Reason)
			case "succeeded":
				sha := e.ArgsSHA
				if len(sha) > 8 {
					sha = sha[:8]
				}
				fmt.Fprintf(&sb, "  %s  tool %s — args %s (%s)\n", t, e.Tool, sha, e.AuthMode)
			default:
				fmt.Fprintf(&sb, "  %s  tool %s %s\n", t, e.Tool, e.Status)
			}
		default:
			fmt.Fprintf(&sb, "  %s  %s\n", t, e.Type)
		}
	}
	return sb.String()
}
