package engine

import (
	"fmt"
	"strings"

	"github.com/agenthof/agenthof/internal/authz"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/registry"
)

// Admit is the registry gate every run passes before it starts, asked in
// this order: the role exists, the workflow exists, the role owns the
// workflow, and the role's allowed_groups admit the invoker. It returns the
// reason to record and false on the first "no", or ("", true). Run calls
// it itself; a caller that must decide synchronously — a server choosing
// whether to accept a run before it starts the goroutine — calls it first
// and records the refusal with RecordRefused, which writes the same event
// Run would have.
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
