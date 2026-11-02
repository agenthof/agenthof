package confiner

import (
	"slices"
	"strings"
)

// childEnv builds the sandboxed program's environment from the requested
// names only, copying each value from environ exactly as podman's `-e NAME`
// does. A name is applied when it is requested AND present in environ;
// nothing else is inherited, PATH included. When tmpdir is set it is applied
// as TMPDIR whether or not TMPDIR was requested, and it replaces the host's
// value. env is sorted by name and applied is the sorted name list a runtime
// attests; both are non-nil even when empty, because exec.Cmd reads a nil Env
// as "inherit the parent's environment".
func childEnv(environ, names []string, tmpdir string) (env, applied []string) {
	have := make(map[string]string, len(environ))
	for _, kv := range environ {
		name, value, _ := strings.Cut(kv, "=")
		have[name] = value
	}
	env, applied = []string{}, []string{}
	for _, name := range names {
		if tmpdir != "" && name == "TMPDIR" {
			continue // the scratch dir supplies TMPDIR below, exactly once
		}
		value, ok := have[name]
		if !ok || slices.Contains(applied, name) {
			continue
		}
		applied = append(applied, name)
		env = append(env, name+"="+value)
	}
	if tmpdir != "" {
		applied = append(applied, "TMPDIR")
		env = append(env, "TMPDIR="+tmpdir)
	}
	slices.Sort(applied)
	slices.SortFunc(env, func(a, b string) int {
		na, _, _ := strings.Cut(a, "=")
		nb, _, _ := strings.Cut(b, "=")
		return strings.Compare(na, nb)
	})
	return env, applied
}
