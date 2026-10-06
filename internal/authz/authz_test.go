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

// TestControlAllows is the control-plane truth table (spec §6, §10):
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
	for _, op := range []string{"apply", "enable", "disable", "repair"} {
		if !KnownControlOp(op) {
			t.Fatalf("%q must be a control op", op)
		}
	}
	for _, op := range []string{"", "*", "all", "Apply", "provision"} {
		if KnownControlOp(op) {
			t.Fatalf("%q must not be a control op", op)
		}
	}
}
