package audit

import (
	"fmt"
	"strings"

	"github.com/agenthof/agenthof/internal/engine"
)

func Render(events []engine.Event) string {
	if len(events) == 0 {
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
	fmt.Fprintf(&sb, "status: %s\n\n", status)
	for _, e := range events {
		t := e.Time.UTC().Format("15:04:05")
		switch e.Type {
		case "workflow_started":
			fmt.Fprintf(&sb, "  %s  workflow started\n", t)
		case "step_started":
			fmt.Fprintf(&sb, "  %s  step %s (agent %s) started\n", t, e.Step, e.Agent)
		case "step_succeeded":
			fmt.Fprintf(&sb, "  %s  step %s succeeded — artifact: %s\n", t, e.Step, e.Artifact)
		case "step_failed":
			fmt.Fprintf(&sb, "  %s  step %s (agent %s) failed — %s\n", t, e.Step, e.Agent, e.Reason)
		case "bounced_back":
			fmt.Fprintf(&sb, "  %s  bounced back to %s\n", t, e.Status)
		case "workflow_finished":
			fmt.Fprintf(&sb, "  %s  workflow finished: %s\n", t, e.Status)
		case "run_refused":
			fmt.Fprintf(&sb, "  %s  run refused — %s\n", t, e.Reason)
		default:
			fmt.Fprintf(&sb, "  %s  %s\n", t, e.Type)
		}
	}
	return sb.String()
}
