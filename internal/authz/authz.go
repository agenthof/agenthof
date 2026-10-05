// Package authz holds the two authorization decisions Agenthof makes from a
// role's declared groups: who may run a role's workflows (GroupsAllow — the
// run-time RBAC the engine enforces) and who may change governance itself
// (ControlAllows — the control-plane gate that apply, the enable/disable kill
// switch, and ledger repair enforce). It is a leaf package — it imports only
// config and identity — so the engine and the CLI share one decision instead
// of two drifting copies.
package authz

import "slices"

// ControlOps is the fixed, enumerable set of control-plane operations a role
// may be granted through its control: list. The set is internal and fixed, so
// there is no widest marker: a grant names each operation it confers.
var ControlOps = []string{"apply", "enable", "disable", "repair"}

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
