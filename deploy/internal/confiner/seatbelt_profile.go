package confiner

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"unicode"
)

// profileInput is everything the SBPL text depends on. Every path is already
// EvalSymlinks-resolved (the kernel matches a rule against the real path, so
// a rule naming /tmp/x never matches /private/tmp/x) and sbplSafe.
type profileInput struct {
	// Scratch is the compartment's private scratch dir; "" when Spec.Scratch
	// is false.
	Scratch string
	// SharedHostScratch adds a read+write allow on the shared host
	// /private/tmp. The backend applies it to EVERY compartment it launches,
	// which is what lets its Opts() report the loosening honestly.
	SharedHostScratch bool
	Paths             []Path
	// DenyRead are read-denied subtrees, in order: the fixed home set, the
	// store root, the PID dir, the spawn root (if any), the operator's
	// deny_read.
	DenyRead []string
	// Traverse are the entries of DenyRead that a compartment must resolve a
	// path THROUGH: the store root (over the stores and the scratch dirs) and
	// the spawn root (over a child's socket dir). Each gets metadata on the
	// root directory itself, as a literal, so its subtree stays denied. An
	// entry that is not in DenyRead produces nothing: the field can only
	// modify a deny, never grant on its own. The PID dir and the home
	// credential stores are never traversed and are not listed.
	Traverse []string
}

// sbplBaseline is the part of every profile that no input changes. Reads are
// allowed host-wide (the tier is host-readable), writes are denied unless a
// later rule scopes them in, direct network is denied, mach-lookup stays open
// except the LaunchServices family a confined `open` would use to make the
// user's unconfined browser carry a request, and signals reach the
// compartment's own descendants only.
var sbplBaseline = []string{
	"(version 1)",
	"(deny default)",
	"(allow process-fork)",
	"(allow process-exec)",
	"(allow sysctl-read)",
	"(allow mach-lookup)",
	`(deny mach-lookup (global-name "com.apple.lsd.mapdb") (global-name "com.apple.lsd.modifydb") (global-name "com.apple.lsd.xpc") (global-name "com.apple.lsd.open"))`,
	"(allow signal (target self))",
	"(allow signal (target children))",
	"(allow file-read*)",
	"(allow file-ioctl)",
	"(deny network*)",
}

// sbplDevAllow is the literal set of device nodes a compartment may write.
// It is never (subpath "/dev"): the operator's live TTYs are /dev/ttys*,
// writable by the same uid, and a broad allow would let a confined process
// write into the operator's own shells.
const sbplDevAllow = `(allow file-write* (literal "/dev/null") (literal "/dev/zero") (literal "/dev/random") (literal "/dev/urandom") (literal "/dev/stdin") (literal "/dev/stdout") (literal "/dev/stderr") (subpath "/dev/fd"))`

// sbplProfile renders one compartment's profile. The order is the security
// contract: in SBPL a later, more specific rule wins, so the read denies come
// first, then the metadata re-grant on the roots the compartment traverses,
// then the compartment's own allows. Each own allow
// (the WORK store, every RW Path, the scratch dir) grants read AND write:
// file-write* alone grants no read, and these subtrees sit under roots the
// denies just closed, so a write-only allow would leave the compartment
// unable to read its own workspace. WORK is bound by the launch's
// -D WORK=<store dir>. The only network allow is the unix-socket rule on
// each RW Path; nothing else in the input can add one.
func sbplProfile(in profileInput) string {
	var b strings.Builder
	line := func(s string) {
		b.WriteString(s)
		b.WriteByte('\n')
	}
	for _, l := range sbplBaseline {
		line(l)
	}
	for _, p := range in.DenyRead {
		line(`(deny file-read* (subpath ` + sbplQuote(p) + `))`)
	}
	// A compartment works INSIDE a denied root: its store and scratch dir
	// under the store root, its socket dir under the spawn root. Resolving a
	// path through the root needs metadata (stat, search) on the root
	// directory itself, which the subpath deny took away along with
	// everything under it: a shell's cd into the store and git init, which
	// stats every ancestor of its work tree, fail with "Operation not
	// permitted" on the root. The literal re-grants metadata on the root
	// directory ONLY. Its contents stay denied: a sibling store's files and
	// metadata and a listing of the root are still refused, and the allows
	// below re-open the compartment's own subtrees. The lines sit after every
	// deny so no later deny shadows them.
	for _, p := range in.Traverse {
		if slices.Contains(in.DenyRead, p) {
			line(`(allow file-read-metadata (literal ` + sbplQuote(p) + `))`)
		}
	}
	line(`(allow file-read* file-write* (subpath (param "WORK")))`)
	for _, p := range in.Paths {
		if p.RW {
			line(`(allow file-read* file-write* (subpath ` + sbplQuote(p.Path) + `))`)
		}
	}
	for _, p := range in.Paths {
		if !p.RW {
			line(`(allow file-read* (subpath ` + sbplQuote(p.Path) + `))`)
		}
	}
	if in.Scratch != "" {
		line(`(allow file-read* file-write* (subpath ` + sbplQuote(in.Scratch) + `))`)
	}
	if in.SharedHostScratch {
		line(`(allow file-read* file-write* (subpath "/private/tmp"))`)
	}
	line(sbplDevAllow)
	for _, p := range in.Paths {
		if p.RW {
			line(`(allow network-bind network-outbound (subpath ` + sbplQuote(p.Path) + `))`)
		}
	}
	return b.String()
}

// sbplQuote wraps a path in SBPL double quotes. The caller has validated it
// with sbplSafe; a path that still fails the check is a programming error, and
// a profile carrying it could close the quote and add rules of its own, so
// the generator refuses to emit it.
func sbplQuote(path string) string {
	if err := sbplSafe(path); err != nil {
		panic("confiner: unsafe path reached the sandbox profile: " + err.Error())
	}
	return `"` + path + `"`
}

// fixedHomeDenies is the fixed read-deny floor under the backend process's
// own home: the credential stores a host-readable compartment must not read.
func fixedHomeDenies(home string) []string {
	return []string{
		filepath.Join(home, ".ssh"),
		filepath.Join(home, ".aws"),
		filepath.Join(home, ".gnupg"),
		filepath.Join(home, ".config", "gh"),
		filepath.Join(home, "Library", "Keychains"),
	}
}

// sbplSafe refuses a path that cannot be placed verbatim inside an SBPL
// string: it must be absolute and free of '"', '\' and control characters,
// so no path can close the quote, escape, or break a line of the profile.
func sbplSafe(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("confiner: %q is not an absolute path", path)
	}
	for _, r := range path {
		if r == '"' || r == '\\' || unicode.IsControl(r) {
			return fmt.Errorf("confiner: path %q contains a character the sandbox profile cannot carry", path)
		}
	}
	return nil
}
