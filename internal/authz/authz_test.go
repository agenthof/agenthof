package authz

import "testing"

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
