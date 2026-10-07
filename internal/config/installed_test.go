package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// installByHand is this task's test-side install, independent of
// StageSnapshot/CommitSnapshot (Task 3): copy src's enumerated files into
// store/<hex> and write the pointer. It returns the hash.
func installByHand(t *testing.T, store, src string) string {
	t.Helper()
	h, err := HashDir(src)
	if err != nil {
		t.Fatal(err)
	}
	files, err := configFiles(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, rel := range files {
		data, err := os.ReadFile(filepath.Join(src, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		writeCfg(t, snapshotDir(store, h), rel, string(data))
	}
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store, InstalledPointer), []byte(h+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return h
}

func sampleConfig(t *testing.T) string {
	t.Helper()
	src := t.TempDir()
	writeCfg(t, src, "agents/planner.yaml", "name: planner\nmodel: fast\ninstruction: plan\noutput: plan\nendpoint: http://127.0.0.1:1\n")
	writeCfg(t, src, "workflows/plan-only.yaml", "name: plan-only\nsteps:\n  - name: plan\n    agent: planner\n")
	writeCfg(t, src, "roles/se.yaml", "name: se\nworkflows: [plan-only]\nallowed_groups: [\"*\"]\n")
	writeCfg(t, src, "roles/ops.yaml", "name: platform-admin\nallowed_groups: [platform-eng]\ncontrol: [apply, enable, disable, repair]\n")
	writeCfg(t, src, "gateway.yaml", "models:\n  fast:\n    endpoint: https://example.test/v1\n    model: m\n    api_key_env: K\n")
	return src
}

func TestInstalledHashAbsentMeansNotInstalled(t *testing.T) {
	store := filepath.Join(t.TempDir(), "installed") // does not even exist yet
	hash, installed, err := InstalledHash(store)
	if err != nil || installed || hash != "" {
		t.Fatalf("got hash=%q installed=%v err=%v; want nothing installed, no error", hash, installed, err)
	}
}

func TestInstalledHashTrimsWhitespaceAndRejectsMalformed(t *testing.T) {
	store := t.TempDir()
	const good = "sha256:3a2f6d0c0df4546527ad1ba5c5ae63cc803851f99614247fcbf38b16b4a5d885"
	if err := os.WriteFile(filepath.Join(store, InstalledPointer), []byte("  "+good+"\r\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hash, installed, err := InstalledHash(store)
	if err != nil || !installed || hash != good {
		t.Fatalf("whitespace must be tolerated: hash=%q installed=%v err=%v", hash, installed, err)
	}
	for _, bad := range []string{"garbage\n", "3a2f6d0c\n", "sha1:" + strings.TrimPrefix(good, "sha256:") + "\n", ""} {
		if err := os.WriteFile(filepath.Join(store, InstalledPointer), []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		_, installed, err := InstalledHash(store)
		if err == nil || installed {
			t.Fatalf("pointer %q must fail closed, got installed=%v err=%v", bad, installed, err)
		}
		if !strings.Contains(err.Error(), "malformed pointer") || !strings.Contains(err.Error(), filepath.Join(store, InstalledPointer)) {
			t.Fatalf("error must name the file and the fault: %v", err)
		}
	}
}

func TestInstalledRolesRoundTrip(t *testing.T) {
	store := filepath.Join(t.TempDir(), "installed")
	src := sampleConfig(t)
	want := installByHand(t, store, src)
	roles, hash, installed, err := InstalledRoles(store)
	if err != nil || !installed {
		t.Fatalf("installed=%v err=%v", installed, err)
	}
	if hash != want {
		t.Fatalf("hash=%q want %q", hash, want)
	}
	if len(roles) != 2 || roles[0].Name != "platform-admin" || roles[1].Name != "se" {
		t.Fatalf("roles=%+v", roles)
	}
	if roles[0].Control == nil || roles[0].Control[0] != "apply" || roles[0].AllowedGroups[0] != "platform-eng" {
		t.Fatalf("platform-admin role not read faithfully: %+v", roles[0])
	}
}

// TestInstalledRolesIgnoresAgentAndGatewayLoadFailures is the upgrade-
// robustness point: a snapshot whose agents file carries a spelling the
// current loader rejects (a bare tool grant) must still yield its roles —
// authz needs roles and nothing else, and a lockout caused by a loader
// change would be a bad outcome the design makes impossible.
func TestInstalledRolesIgnoresAgentAndGatewayLoadFailures(t *testing.T) {
	store := filepath.Join(t.TempDir(), "installed")
	src := sampleConfig(t)
	writeCfg(t, src, "agents/stale.yaml", "name: stale\nmodel: fast\ninstruction: x\noutput: y\ntools:\n  - gh\n")
	writeCfg(t, src, "gateway.yaml", "models: [not-a-map\n")
	if _, errs := LoadDir(src); len(errs) == 0 {
		t.Fatal("fixture must fail LoadDir, or this test proves nothing")
	}
	installByHand(t, store, src)
	roles, _, installed, err := InstalledRoles(store)
	if err != nil || !installed {
		t.Fatalf("roles must still be readable: installed=%v err=%v", installed, err)
	}
	if len(roles) != 2 {
		t.Fatalf("roles=%+v", roles)
	}
}

func TestInstalledRolesFailsClosedOnUnparseableRoleFile(t *testing.T) {
	store := filepath.Join(t.TempDir(), "installed")
	src := sampleConfig(t)
	writeCfg(t, src, "roles/broken.yaml", "name: [unterminated\n")
	hash := installByHand(t, store, src)
	_, got, installed, err := InstalledRoles(store)
	if err == nil {
		t.Fatal("a roles file that cannot be parsed must fail closed")
	}
	if !installed || got != hash {
		t.Fatalf("installed=%v hash=%q: the pointer is still honored, the roles are not", installed, got)
	}
	if !strings.Contains(err.Error(), "installed config "+hash) || !strings.Contains(err.Error(), "roles/broken.yaml") {
		t.Fatalf("error must name the snapshot and the file: %v", err)
	}
}

func TestInstalledRolesFailsClosedWhenSnapshotMissing(t *testing.T) {
	store := filepath.Join(t.TempDir(), "installed")
	hash := installByHand(t, store, sampleConfig(t))
	if err := os.RemoveAll(snapshotDir(store, hash)); err != nil {
		t.Fatal(err)
	}
	_, _, installed, err := InstalledRoles(store)
	if err == nil || !installed {
		t.Fatalf("a pointer naming a missing snapshot must fail closed: installed=%v err=%v", installed, err)
	}
}

// stageAndCommit is the real install, as cmdApply performs it: stage src
// into store, hash the staged copy, commit. It returns the hash.
func stageAndCommit(t *testing.T, store, src string) string {
	t.Helper()
	temp, err := StageSnapshot(store, src)
	if err != nil {
		t.Fatal(err)
	}
	h, err := HashDir(temp)
	if err != nil {
		t.Fatal(err)
	}
	if err := CommitSnapshot(store, temp, h); err != nil {
		t.Fatal(err)
	}
	return h
}

// storeEntries lists the store's top-level names (snapshot dirs, the pointer,
// and any leftover temp files a bug would leave behind).
func storeEntries(t *testing.T, store string) []string {
	t.Helper()
	ents, err := os.ReadDir(store)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

// TestStageSnapshotCopiesOnlyEnumeratedFiles: the copy is by configFiles
// enumeration, so HashDir(copy) == HashDir(src) by construction, and stray
// files — a README, a nested installed/ store, a yaml in an unknown subdir —
// are neither copied nor hashed.
func TestStageSnapshotCopiesOnlyEnumeratedFiles(t *testing.T) {
	store := filepath.Join(t.TempDir(), "installed")
	src := sampleConfig(t)
	writeCfg(t, src, "README.md", "not config\n")
	writeCfg(t, src, "installed/current", "sha256:0000000000000000000000000000000000000000000000000000000000000000\n")
	writeCfg(t, src, "agents/nested/deep.yaml", "name: deep\n")
	writeCfg(t, src, "extras/x.yaml", "name: x\n")
	temp, err := StageSnapshot(store, src)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(filepath.Base(temp), ".staging-") || filepath.Dir(temp) != store {
		t.Fatalf("temp must be a .staging-* dir directly under the store: %s", temp)
	}
	want, _ := HashDir(src)
	got, err := HashDir(temp)
	if err != nil || got != want {
		t.Fatalf("HashDir(copy)=%q err=%v, want %q", got, err, want)
	}
	for _, stray := range []string{"README.md", "installed", "agents/nested", "extras"} {
		if _, err := os.Stat(filepath.Join(temp, stray)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s must not be snapshotted (err=%v)", stray, err)
		}
	}
	for _, rel := range []string{"agents/planner.yaml", "workflows/plan-only.yaml", "roles/ops.yaml", "roles/se.yaml", "gateway.yaml"} {
		if _, err := os.Stat(filepath.Join(temp, rel)); err != nil {
			t.Fatalf("%s missing from the copy: %v", rel, err)
		}
	}
}

func TestStageSnapshotUnreadableSourceLeavesNoTemp(t *testing.T) {
	store := filepath.Join(t.TempDir(), "installed")
	if _, err := StageSnapshot(store, filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("a missing source dir must fail")
	}
	if ents, _ := os.ReadDir(store); len(ents) != 0 {
		t.Fatalf("no temp may remain after a failed stage: %v", ents)
	}
}

// TestStageThenAbandonNeverBecomesCurrent: a staged copy that is never
// committed (validation failed, or the process died) is inert — the pointer
// is untouched and nothing is installed.
func TestStageThenAbandonNeverBecomesCurrent(t *testing.T) {
	store := filepath.Join(t.TempDir(), "installed")
	if _, err := StageSnapshot(store, sampleConfig(t)); err != nil {
		t.Fatal(err)
	}
	if _, installed, err := InstalledHash(store); installed || err != nil {
		t.Fatalf("installed=%v err=%v; want nothing installed", installed, err)
	}
}

func TestCommitSnapshotFlipsPointerAndKeepsOldSnapshot(t *testing.T) {
	store := filepath.Join(t.TempDir(), "installed")
	src := sampleConfig(t)
	a := stageAndCommit(t, store, src)
	raw, err := os.ReadFile(filepath.Join(store, InstalledPointer))
	if err != nil || string(raw) != a+"\n" {
		t.Fatalf("pointer=%q err=%v, want %q", raw, err, a+"\n")
	}
	writeCfg(t, src, "agents/planner.yaml", "name: planner\nmodel: fast\ninstruction: plan harder\noutput: plan\nendpoint: http://127.0.0.1:1\n")
	b := stageAndCommit(t, store, src)
	if a == b {
		t.Fatal("fixture: the edit must change the hash")
	}
	hash, installed, err := InstalledHash(store)
	if err != nil || !installed || hash != b {
		t.Fatalf("after the second commit: hash=%q installed=%v err=%v, want %q", hash, installed, err, b)
	}
	for _, h := range []string{a, b} {
		if _, err := os.Stat(filepath.Join(snapshotDir(store, h), "roles", "ops.yaml")); err != nil {
			t.Fatalf("snapshot %s must be kept intact: %v", h, err)
		}
	}
}

// TestCommitSnapshotIsIdempotent: content-addressed, so re-installing the
// same bytes is a no-op — one snapshot dir, the same pointer, and no
// .staging-* or .current-* leftovers.
func TestCommitSnapshotIsIdempotent(t *testing.T) {
	store := filepath.Join(t.TempDir(), "installed")
	src := sampleConfig(t)
	a := stageAndCommit(t, store, src)
	if again := stageAndCommit(t, store, src); again != a {
		t.Fatalf("hash drifted: %q vs %q", again, a)
	}
	names := storeEntries(t, store)
	if len(names) != 2 {
		t.Fatalf("want exactly the snapshot dir and the pointer, got %v", names)
	}
	for _, n := range names {
		if n != InstalledPointer && n != strings.TrimPrefix(a, "sha256:") {
			t.Fatalf("unexpected store entry %q in %v", n, names)
		}
	}
}

func TestCommitSnapshotRefusesMalformedHashLeavingPointerUnchanged(t *testing.T) {
	store := filepath.Join(t.TempDir(), "installed")
	src := sampleConfig(t)
	a := stageAndCommit(t, store, src)
	temp, err := StageSnapshot(store, src)
	if err != nil {
		t.Fatal(err)
	}
	if err := CommitSnapshot(store, temp, "not-a-hash"); err == nil {
		t.Fatal("a malformed hash must be refused")
	}
	if hash, _, _ := InstalledHash(store); hash != a {
		t.Fatalf("pointer changed on a refused commit: %q", hash)
	}
	_ = os.RemoveAll(temp)
}
