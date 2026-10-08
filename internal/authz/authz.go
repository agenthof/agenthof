// Package authz holds the two authorization decisions Agenthof makes from a
// role's declared groups: who may run a role's workflows (GroupsAllow — the
// run-time RBAC the engine enforces) and who may change governance itself
// (ControlAllows — the control-plane gate every control command enforces:
// apply, the enable/disable kill switch, ledger repair, key provisioning and
// retention pruning). It is a leaf package — it imports only config and
// identity — so the engine and the CLI share one decision instead of two
// drifting copies.
package authz

import (
	"slices"

	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/identity"
)

// ControlOps is the fixed, enumerable set of control-plane operations a role
// may be granted through its control: list. The set is internal and fixed, so
// there is no widest marker: a grant names each operation it confers. The
// validation messages that enumerate the set are built from this slice.
var ControlOps = []string{"apply", "enable", "disable", "repair", "provision", "prune"}

// KnownControlOp reports whether op is one of ControlOps.
func KnownControlOp(op string) bool { return slices.Contains(ControlOps, op) }

// GroupsIntersect reports whether any of the invoker's groups appears,
// literally, in allowedGroups. "*" is just a string here: it matches only an
// invoker group spelled "*".
func GroupsIntersect(invokerGroups, allowedGroups []string) bool {
	for _, g := range invokerGroups {
		if slices.Contains(allowedGroups, g) {
			return true
		}
	}
	return false
}

// GroupsAllow is the run-time default-deny decision: an invoker may run a
// role's workflows iff the role is public — allowed_groups carries the "*"
// marker, which admits any authenticated invoker, including one with no
// groups — or the invoker shares one of its groups. Empty allowed_groups
// denies (fail-closed); apply-time validation rejects such a role, so the
// gate should never see one, but it denies defensively.
func GroupsAllow(invokerGroups, allowedGroups []string) bool {
	return slices.Contains(allowedGroups, "*") || GroupsIntersect(invokerGroups, allowedGroups)
}

// ControlAllows is the control-plane default-deny decision: the invoker may
// perform op iff some role both lists op in its control: grant AND names one
// of the invoker's groups in allowed_groups — membership AND grant, never the
// grant alone. It never honors the "*" marker, on either side: a public role
// grants no control operation, and an invoker claiming the group "*" is not a
// member of anything. Every control command reads the roles it authorizes
// against without validation — the installed snapshot's roles, or, before the
// first apply, the configuration directory's — so the apply-time
// public-control-role rejection cannot be relied on here: this is the guard.
// An op outside
// ControlOps is denied regardless of what a role lists, so a typo in a raw,
// never-applied config grants nothing.
func ControlAllows(roles []config.RoleDef, inv identity.Invoker, op string) bool {
	if !KnownControlOp(op) {
		return false
	}
	for _, r := range roles {
		if !slices.Contains(r.Control, op) {
			continue
		}
		for _, g := range inv.Groups {
			if g != "*" && slices.Contains(r.AllowedGroups, g) {
				return true
			}
		}
	}
	return false
}
