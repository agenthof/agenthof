package authz

import (
	"testing"

	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/identity"
)

// TestGroupsAllow is the run-time RBAC truth table, moved here verbatim from
// the engine's TestRoleAllows (which the next task retires) so the behavior is
// proven unchanged.
func TestGroupsAllow(t *testing.T) {
	cases := []struct {
		name    string
		invoker []string
		allowed []string
		want    bool
	}{
		{"group matches", []string{"finance"}, []string{"finance"}, true},
		{"group mismatch", []string{"eng"}, []string{"finance"}, false},
		{"star allows groupless invoker", nil, []string{"*"}, true},
		{"star allows any invoker", []string{"anything"}, []string{"*"}, true},
		{"empty allowed denies (default-deny)", []string{"finance"}, nil, false},
		{"empty allowed denies groupless", nil, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := GroupsAllow(tc.invoker, tc.allowed); got != tc.want {
				t.Fatalf("GroupsAllow(%v, %v) = %v, want %v", tc.invoker, tc.allowed, got, tc.want)
			}
		})
	}
}

func TestGroupsIntersectIsLiteral(t *testing.T) {
	if GroupsIntersect(nil, []string{"*"}) {
		t.Fatal("a groupless invoker must not intersect anything, star included")
	}
	if !GroupsIntersect([]string{"*"}, []string{"*"}) {
		t.Fatal("GroupsIntersect is literal: \"*\" is just a string here")
	}
	if !GroupsIntersect([]string{"a", "finance"}, []string{"finance"}) {
		t.Fatal("shared group must intersect")
	}
}

// TestControlAllows is the control-plane truth table:
// membership AND grant, never grant alone; "*" is never honored — on either
// side — because enable/disable/repair authorize against an unvalidated
// config dir, so the apply-time public-control-role rejection cannot be
// relied on here.
func TestControlAllows(t *testing.T) {
	admin := config.RoleDef{Name: "platform-admin", AllowedGroups: []string{"platform-eng"}, Control: []string{"apply", "disable"}}
	public := config.RoleDef{Name: "open", AllowedGroups: []string{"*"}, Control: []string{"apply", "disable", "repair"}}
	empty := config.RoleDef{Name: "empty", AllowedGroups: []string{"platform-eng"}, Control: []string{}}
	typo := config.RoleDef{Name: "typo", AllowedGroups: []string{"platform-eng"}, Control: []string{"nuke"}}
	inv := func(groups ...string) identity.Invoker { return identity.Invoker{Subject: "x", Groups: groups} }

	cases := []struct {
		name  string
		roles []config.RoleDef
		inv   identity.Invoker
		op    string
		want  bool
	}{
		{"member + grant allows", []config.RoleDef{admin}, inv("platform-eng"), "apply", true},
		{"member, op not granted denies", []config.RoleDef{admin}, inv("platform-eng"), "repair", false},
		{"grant, non-member denies", []config.RoleDef{admin}, inv("finance"), "apply", false},
		{"no groups denies", []config.RoleDef{admin}, inv(), "apply", false},
		{"public role never grants control (no groups)", []config.RoleDef{public}, inv(), "disable", false},
		{"public role never grants control (real groups)", []config.RoleDef{public}, inv("finance"), "disable", false},
		{"public role never grants control (invoker claims *)", []config.RoleDef{public}, inv("*"), "disable", false},
		{"present-empty control grants nothing", []config.RoleDef{empty}, inv("platform-eng"), "apply", false},
		{"unknown op is denied even when a role lists it", []config.RoleDef{typo}, inv("platform-eng"), "nuke", false},
		{"no roles denies", nil, inv("platform-eng"), "apply", false},
		{"any one granting role suffices", []config.RoleDef{public, admin}, inv("platform-eng"), "disable", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ControlAllows(tc.roles, tc.inv, tc.op); got != tc.want {
				t.Fatalf("ControlAllows(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

func TestControlOpsFixedSet(t *testing.T) {
	for _, op := range []string{"apply", "enable", "disable", "repair", "provision", "prune", "pull", "anchor", "seal"} {
		if !KnownControlOp(op) {
			t.Fatalf("%q must be a control op", op)
		}
	}
	for _, op := range []string{"", "*", "all", "Apply", "deploy"} {
		if KnownControlOp(op) {
			t.Fatalf("%q must not be a control op", op)
		}
	}
}

// TestControlAllowsAnchor: the eighth operation is granted exactly like the
// other seven — membership AND grant; a public role grants no anchor; a
// grant of apply does not imply it; vouch is still not an operation.
func TestControlAllowsAnchor(t *testing.T) {
	inv := identity.Invoker{Subject: "dana@example.com", Groups: []string{"platform-eng"}}
	granting := []config.RoleDef{{Name: "ops", AllowedGroups: []string{"platform-eng"}, Control: []string{"anchor"}}}
	if !ControlAllows(granting, inv, "anchor") {
		t.Fatal("membership AND grant must allow anchor")
	}
	if ControlAllows([]config.RoleDef{{Name: "ops", AllowedGroups: []string{"finance"}, Control: []string{"anchor"}}}, inv, "anchor") {
		t.Fatal("grant without membership must deny")
	}
	if ControlAllows([]config.RoleDef{{Name: "ops", AllowedGroups: []string{"platform-eng"}, Control: []string{"apply", "prune"}}}, inv, "anchor") {
		t.Fatal("apply and prune do not imply anchor")
	}
	if ControlAllows([]config.RoleDef{{Name: "pub", AllowedGroups: []string{"*"}, Control: []string{"anchor"}}}, inv, "anchor") {
		t.Fatal("a public role grants no control operation")
	}
	if KnownControlOp("vouch") {
		t.Fatal("vouch is not a grantable operation")
	}
}

// TestControlAllowsSeal: the ninth operation is granted exactly like the
// other eight — membership AND grant; a public role grants no seal; apply,
// repair and anchor do not imply it.
func TestControlAllowsSeal(t *testing.T) {
	inv := identity.Invoker{Subject: "dana@example.com", Groups: []string{"platform-eng"}}
	if !ControlAllows([]config.RoleDef{{Name: "ops", AllowedGroups: []string{"platform-eng"}, Control: []string{"seal"}}}, inv, "seal") {
		t.Fatal("membership AND grant must allow seal")
	}
	if ControlAllows([]config.RoleDef{{Name: "ops", AllowedGroups: []string{"finance"}, Control: []string{"seal"}}}, inv, "seal") {
		t.Fatal("grant without membership must deny")
	}
	if ControlAllows([]config.RoleDef{{Name: "ops", AllowedGroups: []string{"platform-eng"}, Control: []string{"apply", "repair", "anchor"}}}, inv, "seal") {
		t.Fatal("apply, repair and anchor do not imply seal")
	}
	if ControlAllows([]config.RoleDef{{Name: "pub", AllowedGroups: []string{"*"}, Control: []string{"seal"}}}, inv, "seal") {
		t.Fatal("a public role grants no control operation")
	}
	if ControlOps[len(ControlOps)-1] != "seal" || len(ControlOps) != 9 {
		t.Fatalf("seal is the ninth and last operation: %v", ControlOps)
	}
}

// TestControlAllowsProvisionAndPruneAreOpByOp: the two new operations are
// granted exactly like the old — by name, to a member — and neither implies
// the other; the public marker grants neither on either side.
func TestControlAllowsProvisionAndPruneAreOpByOp(t *testing.T) {
	keys := config.RoleDef{Name: "keys", AllowedGroups: []string{"platform-eng"}, Control: []string{"provision"}}
	retention := config.RoleDef{Name: "retention", AllowedGroups: []string{"ops"}, Control: []string{"prune"}}
	public := config.RoleDef{Name: "open", AllowedGroups: []string{"*"}, Control: []string{"provision", "prune"}}
	inv := func(groups ...string) identity.Invoker { return identity.Invoker{Subject: "x", Groups: groups} }
	cases := []struct {
		name  string
		roles []config.RoleDef
		inv   identity.Invoker
		op    string
		want  bool
	}{
		{"provision granted to a member", []config.RoleDef{keys}, inv("platform-eng"), "provision", true},
		{"provision does not imply prune", []config.RoleDef{keys}, inv("platform-eng"), "prune", false},
		{"prune granted to a member", []config.RoleDef{retention}, inv("ops"), "prune", true},
		{"prune does not imply provision", []config.RoleDef{retention}, inv("ops"), "provision", false},
		{"non-member denied", []config.RoleDef{keys}, inv("ops"), "provision", false},
		{"public role grants no provision", []config.RoleDef{public}, inv("platform-eng"), "provision", false},
		{"public role grants no prune, even to a claimed *", []config.RoleDef{public}, inv("*"), "prune", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ControlAllows(tc.roles, tc.inv, tc.op); got != tc.want {
				t.Fatalf("ControlAllows(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

// TestControlAllowsPullIsOpByOp: pull is granted exactly like every other
// operation — by name, to a member. At this level apply does not imply pull
// and pull does not imply apply: the one implication (a grant of apply
// includes pull) lives where the pull action authorizes, not here. The
// public marker grants pull to nobody on either side.
func TestControlAllowsPullIsOpByOp(t *testing.T) {
	edge := config.RoleDef{Name: "edge", AllowedGroups: []string{"execution-points"}, Control: []string{"pull"}}
	operator := config.RoleDef{Name: "operator", AllowedGroups: []string{"platform-eng"}, Control: []string{"apply"}}
	public := config.RoleDef{Name: "open", AllowedGroups: []string{"*"}, Control: []string{"pull"}}
	inv := func(groups ...string) identity.Invoker { return identity.Invoker{Subject: "x", Groups: groups} }
	cases := []struct {
		name  string
		roles []config.RoleDef
		inv   identity.Invoker
		op    string
		want  bool
	}{
		{"pull granted to a member", []config.RoleDef{edge}, inv("execution-points"), "pull", true},
		{"pull does not imply apply", []config.RoleDef{edge}, inv("execution-points"), "apply", false},
		{"apply does not imply pull here", []config.RoleDef{operator}, inv("platform-eng"), "pull", false},
		{"non-member denied pull", []config.RoleDef{edge}, inv("finance"), "pull", false},
		{"groupless invoker denied pull", []config.RoleDef{edge}, inv(), "pull", false},
		{"public role grants no pull", []config.RoleDef{public}, inv("finance"), "pull", false},
		{"public role grants no pull to a claimed *", []config.RoleDef{public}, inv("*"), "pull", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ControlAllows(tc.roles, tc.inv, tc.op); got != tc.want {
				t.Fatalf("ControlAllows(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

// TestVouchIsNotAGrantableControlOp pins that config vouch is gated by the
// host's own authority, never by a role: "vouch" is not in the grantable set,
// so a role that lists it (in a raw, never-applied config) confers nothing,
// whoever the invoker is.
func TestVouchIsNotAGrantableControlOp(t *testing.T) {
	if KnownControlOp("vouch") {
		t.Fatal(`"vouch" must not be a control op`)
	}
	for _, op := range ControlOps {
		if op == "vouch" {
			t.Fatal(`"vouch" must not appear in ControlOps`)
		}
	}
	roles := []config.RoleDef{
		{Name: "vouchers", AllowedGroups: []string{"platform-eng"}, Control: []string{"vouch", "apply"}},
		{Name: "open", AllowedGroups: []string{"*"}, Control: []string{"vouch"}},
	}
	for _, inv := range []identity.Invoker{
		{Subject: "x", Groups: []string{"platform-eng"}},
		{Subject: "x", Groups: []string{"*"}},
		{Subject: "x"},
	} {
		if ControlAllows(roles, inv, "vouch") {
			t.Fatalf("ControlAllows must deny vouch regardless of roles, invoker %+v", inv)
		}
	}
}
