package engine

import "testing"

func TestRoleAllows(t *testing.T) {
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
			if got := roleAllows(tc.invoker, tc.allowed); got != tc.want {
				t.Fatalf("roleAllows(%v, %v) = %v, want %v", tc.invoker, tc.allowed, got, tc.want)
			}
		})
	}
}
