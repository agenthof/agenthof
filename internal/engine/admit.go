package engine

import (
	"fmt"
	"strings"

	"github.com/agenthof/agenthof/internal/authz"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/registry"
)

// RefuseSpawnOnlyRoot is the root-run-only gate: it refuses a workflow with
// any step whose agent is spawn-only, because such an agent may run only as a
// spawned child. It is deliberately separate from Admit, which child spawns
// also pass; only a caller starting a ROOT run (Run with no Parent, or a
// server deciding synchronously before it accepts one) asks it.
func RefuseSpawnOnlyRoot(reg *registry.Registry, workflow string) (reason string, refused bool) {
	wf, ok := reg.Workflow(workflow)
	if !ok {
		return "", false
	}
	for _, st := range wf.Steps {
		if a, ok := reg.Agent(st.Agent); ok && a.SpawnOnly() {
			return fmt.Sprintf(reasonSpawnOnlyRoot, a.Name), true
		}
	}
	return "", false
}

// Admit is the registry gate every run passes before it starts, asked in
// this order: the role exists, the workflow exists, the role owns the
// workflow, and the role's allowed_groups admit the invoker. It returns the
// reason to record and false on the first "no", or ("", true). Run calls
// it itself; a caller that must decide synchronously — a server choosing
// whether to accept a run before it starts the goroutine — calls it first
// and records the refusal with RecordRefused, which writes the same event
// Run would have. A root run also passes RefuseSpawnOnlyRoot, which Admit
// leaves out because child spawns pass Admit too.
func Admit(reg *registry.Registry, role, workflow string, inv identity.Invoker) (reason string, ok bool) {
	ro, ok := reg.Role(role)
	if !ok {
		return fmt.Sprintf("role %q is not in the registry", role), false
	}
	if _, ok := reg.Workflow(workflow); !ok {
		return fmt.Sprintf("workflow %q is not in the registry", workflow), false
	}
	if !reg.RoleOwnsWorkflow(role, workflow) {
		return fmt.Sprintf("role %q does not own workflow %q", role, workflow), false
	}
	if !authz.GroupsAllow(inv.Groups, ro.AllowedGroups) {
		return fmt.Sprintf(
			"role %q requires membership in one of its allowed groups (%s); the invoker's groups don't qualify",
			role, strings.Join(ro.AllowedGroups, ", ")), false
	}
	return "", true
}
