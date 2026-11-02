package confiner

import (
	"slices"
	"strings"
	"testing"
)

// The golden body IS the rule order: a later, more specific rule wins in
// SBPL, so the read denies must precede the compartment's own allows, and
// every own/RW allow must grant read AND write.
func TestSBPLProfileGolden(t *testing.T) {
	got := sbplProfile(profileInput{Scratch: "/private/var/s/.scratch/refexec-01",
		Paths:    []Path{{Path: "/private/var/sp/r-1", RW: true}, {Path: "/opt/ro", RW: false}},
		DenyRead: append(fixedHomeDenies("/home/op"), "/private/var/s", "/private/var/p", "/private/var/sp", "/home/op/ledger"),
		Traverse: []string{"/private/var/s", "/private/var/sp"}})
	want := `(version 1)
(deny default)
(allow process-fork)
(allow process-exec)
(allow sysctl-read)
(allow mach-lookup)
(deny mach-lookup (global-name "com.apple.lsd.mapdb") (global-name "com.apple.lsd.modifydb") (global-name "com.apple.lsd.xpc") (global-name "com.apple.lsd.open"))
(allow signal (target self))
(allow signal (target children))
(allow file-read*)
(allow file-ioctl)
(deny network*)
(deny file-read* (subpath "/home/op/.ssh"))
(deny file-read* (subpath "/home/op/.aws"))
(deny file-read* (subpath "/home/op/.gnupg"))
(deny file-read* (subpath "/home/op/.config/gh"))
(deny file-read* (subpath "/home/op/Library/Keychains"))
(deny file-read* (subpath "/private/var/s"))
(deny file-read* (subpath "/private/var/p"))
(deny file-read* (subpath "/private/var/sp"))
(deny file-read* (subpath "/home/op/ledger"))
(allow file-read-metadata (literal "/private/var/s"))
(allow file-read-metadata (literal "/private/var/sp"))
(allow file-read* file-write* (subpath (param "WORK")))
(allow file-read* file-write* (subpath "/private/var/sp/r-1"))
(allow file-read* (subpath "/opt/ro"))
(allow file-read* file-write* (subpath "/private/var/s/.scratch/refexec-01"))
(allow file-write* (literal "/dev/null") (literal "/dev/zero") (literal "/dev/random") (literal "/dev/urandom") (literal "/dev/stdin") (literal "/dev/stdout") (literal "/dev/stderr") (subpath "/dev/fd"))
(allow network-bind network-outbound (subpath "/private/var/sp/r-1"))
`
	if got != want {
		t.Fatalf("profile:\n%s\nwant:\n%s", got, want)
	}
}

// The loosened backend's variant: the shared host scratch allow sits between
// the compartment's own allows and the /dev line, and nothing else moves.
func TestSBPLProfileGoldenSharedHostScratch(t *testing.T) {
	got := sbplProfile(profileInput{Scratch: "/private/var/s/.scratch/refexec-01", SharedHostScratch: true,
		Paths:    []Path{{Path: "/private/var/sp/r-1", RW: true}},
		DenyRead: []string{"/private/var/s", "/private/var/p"},
		Traverse: []string{"/private/var/s"}})
	want := `(version 1)
(deny default)
(allow process-fork)
(allow process-exec)
(allow sysctl-read)
(allow mach-lookup)
(deny mach-lookup (global-name "com.apple.lsd.mapdb") (global-name "com.apple.lsd.modifydb") (global-name "com.apple.lsd.xpc") (global-name "com.apple.lsd.open"))
(allow signal (target self))
(allow signal (target children))
(allow file-read*)
(allow file-ioctl)
(deny network*)
(deny file-read* (subpath "/private/var/s"))
(deny file-read* (subpath "/private/var/p"))
(allow file-read-metadata (literal "/private/var/s"))
(allow file-read* file-write* (subpath (param "WORK")))
(allow file-read* file-write* (subpath "/private/var/sp/r-1"))
(allow file-read* file-write* (subpath "/private/var/s/.scratch/refexec-01"))
(allow file-read* file-write* (subpath "/private/tmp"))
(allow file-write* (literal "/dev/null") (literal "/dev/zero") (literal "/dev/random") (literal "/dev/urandom") (literal "/dev/stdin") (literal "/dev/stdout") (literal "/dev/stderr") (subpath "/dev/fd"))
(allow network-bind network-outbound (subpath "/private/var/sp/r-1"))
`
	if got != want {
		t.Fatalf("profile:\n%s\nwant:\n%s", got, want)
	}
}

func TestFixedHomeDenies(t *testing.T) {
	want := []string{"/home/op/.ssh", "/home/op/.aws", "/home/op/.gnupg", "/home/op/.config/gh", "/home/op/Library/Keychains"}
	if got := fixedHomeDenies("/home/op"); !slices.Equal(got, want) {
		t.Fatalf("fixedHomeDenies = %q, want %q", got, want)
	}
	// A trailing slash on the home must not produce "//.ssh", which no SBPL
	// subpath rule would match.
	if got := fixedHomeDenies("/home/op/"); !slices.Equal(got, want) {
		t.Fatalf("fixedHomeDenies with a trailing slash = %q, want %q", got, want)
	}
}

const (
	workAllow   = `(allow file-read* file-write* (subpath (param "WORK")))`
	sharedAllow = `(allow file-read* file-write* (subpath "/private/tmp"))`
	devAllow    = `(allow file-write* (literal "/dev/null") (literal "/dev/zero") (literal "/dev/random") (literal "/dev/urandom") (literal "/dev/stdin") (literal "/dev/stdout") (literal "/dev/stderr") (subpath "/dev/fd"))`
)

// profileLines splits a profile into its lines and fails on a profile that
// does not end with exactly one newline.
func profileLines(t *testing.T, profile string) []string {
	t.Helper()
	if !strings.HasSuffix(profile, "\n") || strings.HasSuffix(profile, "\n\n") {
		t.Fatalf("profile must end with exactly one newline:\n%s", profile)
	}
	return strings.Split(strings.TrimSuffix(profile, "\n"), "\n")
}

// mustIndex returns the index of the one line equal to want.
func mustIndex(t *testing.T, lines []string, want string) int {
	t.Helper()
	i := slices.Index(lines, want)
	if i < 0 {
		t.Fatalf("line %q missing from:\n%s", want, strings.Join(lines, "\n"))
	}
	if slices.Index(lines[i+1:], want) >= 0 {
		t.Fatalf("line %q appears more than once in:\n%s", want, strings.Join(lines, "\n"))
	}
	return i
}

// checkNetworkAllows pins the ONLY network allow the profile may carry: the
// unix-socket rule, one per RW Path, in that exact form. Everything else
// network-shaped is the baseline's (deny network*).
func checkNetworkAllows(t *testing.T, lines []string, rw []string) {
	t.Helper()
	var got []string
	for _, l := range lines {
		if strings.HasPrefix(l, "(allow network") {
			got = append(got, l)
		}
	}
	var want []string
	for _, p := range rw {
		want = append(want, `(allow network-bind network-outbound (subpath "`+p+`"))`)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("network allows = %q, want exactly %q", got, want)
	}
	if slices.Index(lines, "(deny network*)") < 0 {
		t.Fatalf("(deny network*) missing:\n%s", strings.Join(lines, "\n"))
	}
}

// checkForbidden pins the constructs no input may ever produce: a broad /dev
// write (the operator's TTYs live there), signalling arbitrary host
// processes, any network allow beyond the per-RW-Path unix-socket rule, and
// a metadata re-grant on a SUBTREE (only the literal root directory may get
// one).
func checkForbidden(t *testing.T, profile string) {
	t.Helper()
	for _, bad := range []string{`(subpath "/dev")`, `(target others)`, `(allow network*)`, `(allow network-outbound)`, `(allow network-bind)`, `(allow network-inbound`, `(allow file-write*)`, `(allow default)`, `(allow file-read-metadata (subpath`, `(allow file-read-metadata)`} {
		if strings.Contains(profile, bad) {
			t.Errorf("profile contains forbidden %q:\n%s", bad, profile)
		}
	}
	for _, l := range profileLines(t, profile) {
		if strings.Contains(l, "file-write*") && strings.Contains(l, "subpath") && !strings.HasPrefix(l, "(allow file-read* file-write* (subpath ") && l != devAllow {
			t.Errorf("a write-only subpath allow (unreadable to the compartment): %q", l)
		}
	}
}

func TestSBPLProfileInvariants(t *testing.T) {
	denies := append(fixedHomeDenies("/home/op"), "/private/var/s", "/private/var/p")

	t.Run("no scratch, no scratch line", func(t *testing.T) {
		p := sbplProfile(profileInput{Paths: []Path{{Path: "/x", RW: true}}, DenyRead: denies})
		if strings.Contains(p, ".scratch") {
			t.Fatalf("Scratch \"\" still emitted a scratch line:\n%s", p)
		}
		if strings.Contains(p, sharedAllow) {
			t.Fatalf("SharedHostScratch off still emitted the shared allow:\n%s", p)
		}
		checkForbidden(t, p)
		lines := profileLines(t, p)
		checkNetworkAllows(t, lines, []string{"/x"})
		// With no scratch, WORK/RW/RO allows are the last file lines before /dev.
		if lines[mustIndex(t, lines, devAllow)-1] != `(allow file-read* file-write* (subpath "/x"))` {
			t.Fatalf("the /dev line must follow the last own allow:\n%s", p)
		}
	})

	t.Run("shared host scratch sits after the scratch allow and before /dev", func(t *testing.T) {
		p := sbplProfile(profileInput{Scratch: "/private/var/s/.scratch/c", SharedHostScratch: true, Paths: []Path{{Path: "/x", RW: true}}, DenyRead: denies})
		checkForbidden(t, p)
		lines := profileLines(t, p)
		dev := mustIndex(t, lines, devAllow)
		if lines[dev-1] != sharedAllow {
			t.Fatalf("line before /dev = %q, want the shared allow:\n%s", lines[dev-1], p)
		}
		if lines[dev-2] != `(allow file-read* file-write* (subpath "/private/var/s/.scratch/c"))` {
			t.Fatalf("line before the shared allow = %q, want the scratch allow:\n%s", lines[dev-2], p)
		}
		checkNetworkAllows(t, lines, []string{"/x"})
	})

	t.Run("shared host scratch without a scratch dir follows the own allows", func(t *testing.T) {
		p := sbplProfile(profileInput{SharedHostScratch: true, Paths: []Path{{Path: "/ro", RW: false}}, DenyRead: denies})
		checkForbidden(t, p)
		lines := profileLines(t, p)
		dev := mustIndex(t, lines, devAllow)
		if lines[dev-1] != sharedAllow || lines[dev-2] != `(allow file-read* (subpath "/ro"))` {
			t.Fatalf("want … RO allow, shared allow, /dev; got:\n%s", p)
		}
		if strings.Contains(p, ".scratch") {
			t.Fatalf("no scratch dir, yet a scratch line:\n%s", p)
		}
	})

	t.Run("own store is read and write, after every deny", func(t *testing.T) {
		p := sbplProfile(profileInput{Scratch: "/private/var/s/.scratch/c", Paths: []Path{{Path: "/x", RW: true}}, DenyRead: denies})
		checkForbidden(t, p)
		lines := profileLines(t, p)
		work := mustIndex(t, lines, workAllow)
		if strings.Contains(p, `(allow file-write* (subpath (param "WORK")))`) {
			t.Fatalf("a write-only WORK allow leaves the store unreadable:\n%s", p)
		}
		var denyCount int
		for i, l := range lines {
			if strings.HasPrefix(l, "(deny file-read*") {
				denyCount++
				if i >= work {
					t.Errorf("deny %q at %d comes after the WORK allow at %d: it would shadow the own store", l, i, work)
				}
			}
		}
		if denyCount != len(denies) {
			t.Fatalf("deny-read lines = %d, want %d", denyCount, len(denies))
		}
		// Each deny names its path verbatim, in the given order.
		var got []string
		for _, l := range lines {
			if strings.HasPrefix(l, "(deny file-read* (subpath ") {
				got = append(got, strings.TrimSuffix(strings.TrimPrefix(l, `(deny file-read* (subpath "`), `"))`))
			}
		}
		if !slices.Equal(got, denies) {
			t.Fatalf("deny order = %q, want %q", got, denies)
		}
		// The allows that sit under just-denied roots come after the denies.
		for _, allow := range []string{`(allow file-read* file-write* (subpath "/x"))`, `(allow file-read* file-write* (subpath "/private/var/s/.scratch/c"))`} {
			if mustIndex(t, lines, allow) <= work {
				t.Errorf("%q must follow the WORK allow", allow)
			}
		}
	})

	t.Run("traversable roots get a literal metadata allow after every deny and before WORK", func(t *testing.T) {
		p := sbplProfile(profileInput{Paths: []Path{{Path: "/x", RW: true}}, DenyRead: append(denies, "/private/var/sp", "/home/op/ledger"), Traverse: []string{"/private/var/s", "/private/var/sp"}})
		checkForbidden(t, p)
		lines := profileLines(t, p)
		work := mustIndex(t, lines, workAllow)
		storeMeta := mustIndex(t, lines, `(allow file-read-metadata (literal "/private/var/s"))`)
		spawnMeta := mustIndex(t, lines, `(allow file-read-metadata (literal "/private/var/sp"))`)
		// Exactly one metadata line per traversable root, in Traverse order,
		// directly before the WORK allow, so no later deny can shadow them.
		if storeMeta != work-2 || spawnMeta != work-1 {
			t.Fatalf("metadata allows at %d and %d, WORK at %d:\n%s", storeMeta, spawnMeta, work, p)
		}
		for i, l := range lines {
			if strings.HasPrefix(l, "(deny file-read*") && i > storeMeta {
				t.Errorf("deny %q at %d comes after a metadata allow at %d", l, i, storeMeta)
			}
		}
		if n := strings.Count(p, "file-read-metadata"); n != 2 {
			t.Fatalf("file-read-metadata appears %d times, want 2:\n%s", n, p)
		}
		// The PID dir and the home credential stores are denied without one.
		for _, never := range []string{"/private/var/p", "/home/op/.ssh", "/home/op/ledger"} {
			if strings.Contains(p, `(allow file-read-metadata (literal "`+never+`"))`) {
				t.Errorf("%s got a metadata allow:\n%s", never, p)
			}
		}
	})

	t.Run("a metadata allow is only ever a modifier on a deny", func(t *testing.T) {
		// A Traverse entry that no deny names grants nothing: the field can
		// re-open the directory entry of a denied root, never widen on its own.
		p := sbplProfile(profileInput{DenyRead: denies, Traverse: []string{"/elsewhere"}})
		checkForbidden(t, p)
		if strings.Contains(p, "file-read-metadata") {
			t.Fatalf("a Traverse entry outside DenyRead produced a line:\n%s", p)
		}
		// No Traverse, no metadata line at all.
		p = sbplProfile(profileInput{DenyRead: denies})
		if strings.Contains(p, "file-read-metadata") {
			t.Fatalf("no Traverse, yet a metadata line:\n%s", p)
		}
	})

	t.Run("an RO path yields no unix-socket rule", func(t *testing.T) {
		p := sbplProfile(profileInput{Paths: []Path{{Path: "/ro", RW: false}}, DenyRead: denies})
		checkForbidden(t, p)
		lines := profileLines(t, p)
		checkNetworkAllows(t, lines, nil)
		if strings.Contains(p, "network-bind") {
			t.Fatalf("RO path produced a network-bind line:\n%s", p)
		}
		mustIndex(t, lines, `(allow file-read* (subpath "/ro"))`)
		if strings.Contains(p, `file-write* (subpath "/ro")`) {
			t.Fatalf("RO path became writable:\n%s", p)
		}
	})

	t.Run("one RW path yields exactly one network rule, nothing else can add one", func(t *testing.T) {
		p := sbplProfile(profileInput{Scratch: "/private/var/s/.scratch/c", SharedHostScratch: true,
			Paths: []Path{{Path: "/x", RW: true}, {Path: "/ro"}}, DenyRead: append(denies, "/home/op/ledger")})
		checkForbidden(t, p)
		lines := profileLines(t, p)
		checkNetworkAllows(t, lines, []string{"/x"})
		if strings.Count(p, "network-bind") != 1 {
			t.Fatalf("network-bind count = %d, want 1:\n%s", strings.Count(p, "network-bind"), p)
		}
		// The unix-socket rule is the last line of the profile.
		if lines[len(lines)-1] != `(allow network-bind network-outbound (subpath "/x"))` {
			t.Fatalf("last line = %q", lines[len(lines)-1])
		}
	})

	t.Run("two RW paths yield two network rules in order", func(t *testing.T) {
		p := sbplProfile(profileInput{Paths: []Path{{Path: "/b", RW: true}, {Path: "/a", RW: true}}})
		checkForbidden(t, p)
		lines := profileLines(t, p)
		checkNetworkAllows(t, lines, []string{"/b", "/a"})
		if lines[len(lines)-1] != `(allow network-bind network-outbound (subpath "/a"))` || lines[len(lines)-2] != `(allow network-bind network-outbound (subpath "/b"))` {
			t.Fatalf("network rules out of order:\n%s", p)
		}
	})

	t.Run("empty input is the bare baseline", func(t *testing.T) {
		p := sbplProfile(profileInput{})
		checkForbidden(t, p)
		lines := profileLines(t, p)
		checkNetworkAllows(t, lines, nil)
		if lines[0] != "(version 1)" || lines[1] != "(deny default)" {
			t.Fatalf("header:\n%s", p)
		}
		if lines[mustIndex(t, lines, devAllow)-1] != workAllow || lines[len(lines)-1] != devAllow {
			t.Fatalf("bare baseline should end WORK allow, /dev:\n%s", p)
		}
		if strings.Contains(p, "(deny file-read*") {
			t.Fatalf("no DenyRead, yet a deny line:\n%s", p)
		}
	})
}

// A path that could close an SBPL string must never reach the profile text;
// the caller validates first, and the generator refuses rather than emit it.
func TestSBPLProfileRefusesAnUnsafePath(t *testing.T) {
	for _, in := range []profileInput{
		{DenyRead: []string{`/a")) (allow network* (subpath "/`}},
		{Paths: []Path{{Path: "rel", RW: true}}},
		{Scratch: "/s\n(allow network*)"},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("sbplProfile(%+v) emitted a profile for an unsafe path", in)
				}
			}()
			sbplProfile(in)
		}()
	}
}

func TestSBPLSafe(t *testing.T) {
	for _, tc := range []struct {
		path string
		ok   bool
	}{
		{"/ok/path", true},
		{"/", true},
		{"/home/op/Library/Application Support", true},
		{"rel", false},
		{"", false},
		{`/a"b`, false},
		{`/a\b`, false},
		{"/a\nb", false},
		{"/a\tb", false},
		{"/a\x00b", false},
		{"/a\x7fb", false},
		{"/a\x1bb", false},
	} {
		err := sbplSafe(tc.path)
		if tc.ok && err != nil {
			t.Errorf("sbplSafe(%q) = %v, want nil", tc.path, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("sbplSafe(%q) = nil, want an error", tc.path)
		}
	}
}
