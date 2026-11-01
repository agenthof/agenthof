package confiner

import (
	"slices"
	"testing"
)

func TestChildEnv(t *testing.T) {
	host := []string{"PATH=/usr/bin", "A=1", "B=2", "TMPDIR=/host"}

	t.Run("requested and present, scratch TMPDIR overrides the host's", func(t *testing.T) {
		env, applied := childEnv(host, []string{"B", "A", "UNSET", "TMPDIR"}, "/s/.scratch/x")
		if want := []string{"A=1", "B=2", "TMPDIR=/s/.scratch/x"}; !slices.Equal(env, want) {
			t.Fatalf("env = %q, want %q", env, want)
		}
		if want := []string{"A", "B", "TMPDIR"}; !slices.Equal(applied, want) {
			t.Fatalf("applied = %q, want %q", applied, want)
		}
		for _, kv := range env {
			if kv == "PATH=/usr/bin" || kv == "TMPDIR=/host" {
				t.Fatalf("host value leaked into the child: %q", kv)
			}
		}
	})

	t.Run("PATH passes only when requested", func(t *testing.T) {
		env, applied := childEnv(host, []string{"PATH"}, "")
		if !slices.Equal(env, []string{"PATH=/usr/bin"}) || !slices.Equal(applied, []string{"PATH"}) {
			t.Fatalf("env = %q applied = %q", env, applied)
		}
	})

	t.Run("a scratch TMPDIR is applied even when not requested", func(t *testing.T) {
		env, applied := childEnv(host, nil, "/s/.scratch/y")
		if !slices.Equal(env, []string{"TMPDIR=/s/.scratch/y"}) || !slices.Equal(applied, []string{"TMPDIR"}) {
			t.Fatalf("env = %q applied = %q", env, applied)
		}
	})

	t.Run("a requested host TMPDIR passes through without a scratch dir", func(t *testing.T) {
		env, applied := childEnv(host, []string{"TMPDIR"}, "")
		if !slices.Equal(env, []string{"TMPDIR=/host"}) || !slices.Equal(applied, []string{"TMPDIR"}) {
			t.Fatalf("env = %q applied = %q", env, applied)
		}
	})

	t.Run("nothing applied is empty, never nil", func(t *testing.T) {
		// exec.Cmd treats a nil Env as "inherit the parent's environment", so
		// an empty child environment must be a non-nil empty slice.
		env, applied := childEnv(host, []string{"UNSET", "ALSO_UNSET"}, "")
		if env == nil || len(env) != 0 {
			t.Fatalf("env = %#v, want a non-nil empty slice", env)
		}
		if applied == nil || len(applied) != 0 {
			t.Fatalf("applied = %#v, want a non-nil empty slice", applied)
		}
		env, applied = childEnv(nil, nil, "")
		if env == nil || applied == nil {
			t.Fatalf("env = %#v applied = %#v, want non-nil", env, applied)
		}
	})

	t.Run("duplicates are applied once", func(t *testing.T) {
		env, applied := childEnv(host, []string{"A", "A", "TMPDIR", "TMPDIR"}, "/s/.scratch/z")
		if !slices.Equal(env, []string{"A=1", "TMPDIR=/s/.scratch/z"}) || !slices.Equal(applied, []string{"A", "TMPDIR"}) {
			t.Fatalf("env = %q applied = %q", env, applied)
		}
	})

	t.Run("a value keeps its own equals signs", func(t *testing.T) {
		env, _ := childEnv([]string{"Q=a=b=c", "EMPTY="}, []string{"Q", "EMPTY"}, "")
		if !slices.Equal(env, []string{"EMPTY=", "Q=a=b=c"}) {
			t.Fatalf("env = %q", env)
		}
	})
}
