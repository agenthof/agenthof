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
		writeCfg(t, SnapshotDir(store, h), rel, string(data))
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

// TestInstalledRolesFailsClosedOnDamagedSnapshot: a snapshot that is present
// (the pointer still names it) but has lost its roles — its roles/ directory
// gone, or the <hex> entry replaced by a file — must fail closed with an error
// naming the snapshot, NOT read back as an empty role list that silently
// denies everyone. Every installed snapshot passed the no-apply-floor, so zero
// roles is always damage.
func TestInstalledRolesFailsClosedOnDamagedSnapshot(t *testing.T) {
	t.Run("roles directory gone", func(t *testing.T) {
		store := filepath.Join(t.TempDir(), "installed")
		hash := installByHand(t, store, sampleConfig(t))
		if err := os.RemoveAll(filepath.Join(SnapshotDir(store, hash), "roles")); err != nil {
			t.Fatal(err)
		}
		_, got, installed, err := InstalledRoles(store)
		if err == nil || !installed || got != hash {
			t.Fatalf("installed=%v hash=%q err=%v; want fail-closed naming the snapshot", installed, got, err)
		}
		if !strings.Contains(err.Error(), "installed config "+hash) || !strings.Contains(err.Error(), "no roles") {
			t.Fatalf("error must name the snapshot and the fault: %v", err)
		}
	})
	t.Run("snapshot entry is a file", func(t *testing.T) {
		store := filepath.Join(t.TempDir(), "installed")
		hash := installByHand(t, store, sampleConfig(t))
		if err := os.RemoveAll(SnapshotDir(store, hash)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(SnapshotDir(store, hash), []byte("not a dir\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, installed, err := InstalledRoles(store)
		if err == nil || !installed {
			t.Fatalf("installed=%v err=%v; want fail-closed", installed, err)
		}
		if !strings.Contains(err.Error(), "no roles") {
			t.Fatalf("error must name the fault: %v", err)
		}
	})
}

func TestInstalledRolesFailsClosedWhenSnapshotMissing(t *testing.T) {
	store := filepath.Join(t.TempDir(), "installed")
	hash := installByHand(t, store, sampleConfig(t))
	if err := os.RemoveAll(SnapshotDir(store, hash)); err != nil {
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
		if _, err := os.Stat(filepath.Join(SnapshotDir(store, h), "roles", "ops.yaml")); err != nil {
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

// TestCommitSnapshotRefusesCorruptExistingSnapshot: when the <hex>/ directory
// is already present but corrupt (here, its roles/ was lost), re-applying the
// identical config must NOT silently flip the pointer onto the damaged dir and
// report success — it must fail closed, naming the snapshot, leaving the
// pointer unchanged.
func TestCommitSnapshotRefusesCorruptExistingSnapshot(t *testing.T) {
	store := filepath.Join(t.TempDir(), "installed")
	src := sampleConfig(t)
	a := stageAndCommit(t, store, src)
	if err := os.RemoveAll(filepath.Join(SnapshotDir(store, a), "roles")); err != nil {
		t.Fatal(err)
	}
	temp, err := StageSnapshot(store, src)
	if err != nil {
		t.Fatal(err)
	}
	err = CommitSnapshot(store, temp, a)
	if err == nil {
		t.Fatal("committing onto a corrupt existing snapshot must fail closed")
	}
	if !strings.Contains(err.Error(), "corrupt") || !strings.Contains(err.Error(), a) {
		t.Fatalf("error must name the corruption and the snapshot: %v", err)
	}
	if hash, _, _ := InstalledHash(store); hash != a {
		t.Fatalf("pointer changed on a refused commit: %q", hash)
	}
	_ = os.RemoveAll(temp)
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

func TestLoadInstalledRoundTripsTheWholeSnapshot(t *testing.T) {
	store := filepath.Join(t.TempDir(), "installed")
	src := sampleConfig(t)
	want := installByHand(t, store, src)
	cfg, hash, installed, errs := LoadInstalled(store)
	if len(errs) != 0 || !installed {
		t.Fatalf("installed=%v errs=%v", installed, errs)
	}
	if hash != want {
		t.Fatalf("hash must be the pointer's value verbatim: got %q want %q", hash, want)
	}
	if len(cfg.Agents) != 1 || len(cfg.Workflows) != 1 || len(cfg.Roles) != 2 || len(cfg.Gateway.Models) != 1 {
		t.Fatalf("every file LoadDir reads must be present: %+v", cfg)
	}
}

func TestLoadInstalledAbsentPointerMeansNotInstalled(t *testing.T) {
	store := filepath.Join(t.TempDir(), "installed") // does not exist
	cfg, hash, installed, errs := LoadInstalled(store)
	if installed || hash != "" || len(errs) != 0 || len(cfg.Roles) != 0 {
		t.Fatalf("got installed=%v hash=%q errs=%v", installed, hash, errs)
	}
}

func TestLoadInstalledMalformedPointerIsOneError(t *testing.T) {
	store := t.TempDir()
	if err := os.WriteFile(filepath.Join(store, InstalledPointer), []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, hash, installed, errs := LoadInstalled(store)
	if installed || hash != "" || len(errs) != 1 || !strings.Contains(errs[0].Error(), "malformed pointer") {
		t.Fatalf("got installed=%v hash=%q errs=%v", installed, hash, errs)
	}
}

func TestLoadInstalledMissingSnapshotNamesTheHash(t *testing.T) {
	store := filepath.Join(t.TempDir(), "installed")
	hash := installByHand(t, store, sampleConfig(t))
	if err := os.RemoveAll(SnapshotDir(store, hash)); err != nil {
		t.Fatal(err)
	}
	_, got, installed, errs := LoadInstalled(store)
	if !installed || got != hash || len(errs) != 1 {
		t.Fatalf("a present pointer naming a missing snapshot is installed-with-an-error: installed=%v hash=%q errs=%v", installed, got, errs)
	}
	if !strings.Contains(errs[0].Error(), "installed config "+hash+":") {
		t.Fatalf("the error must name the snapshot: %v", errs[0])
	}
}

// TestLoadInstalledReportsEveryFileErrorWhileRolesStillRead: the full read
// fails closed on a file that no longer parses — naming the snapshot on every
// error — whereas the roles-only read (InstalledRoles) on the same snapshot
// still yields roles, so authorization survives a loader change.
func TestLoadInstalledReportsEveryFileErrorWhileRolesStillRead(t *testing.T) {
	store := filepath.Join(t.TempDir(), "installed")
	src := sampleConfig(t)
	writeCfg(t, src, "agents/stale.yaml", "name: stale\nmodel: fast\ninstruction: x\noutput: y\ntools:\n  - gh\n")
	writeCfg(t, src, "gateway.yaml", "models: [not-a-map\n")
	_, want := LoadDir(src)
	if len(want) == 0 {
		t.Fatal("fixture must fail LoadDir, or this test proves nothing")
	}
	hash := installByHand(t, store, src)
	_, got, installed, errs := LoadInstalled(store)
	if !installed || got != hash || len(errs) != len(want) {
		t.Fatalf("want every LoadDir error (%d): installed=%v hash=%q errs=%v", len(want), installed, got, errs)
	}
	for _, e := range errs {
		if !strings.HasPrefix(e.Error(), "installed config "+hash+": ") {
			t.Fatalf("every error must name the snapshot: %v", e)
		}
	}
	if roles, _, _, err := InstalledRoles(store); err != nil || len(roles) != 2 {
		t.Fatalf("the roles-only read must still work: roles=%d err=%v", len(roles), err)
	}
}

// mismatchText builds the exact verify-on-read error for a snapshot named
// hash whose bytes now hash as got.
func mismatchText(hash, got string) string {
	return "installed config " + hash + ": snapshot hashes as " + got + ", not as its pointer"
}

// tamperSnapshot appends a comment to one file inside the installed
// snapshot — the in-place edit verify-on-read exists to catch — and returns
// what the directory hashes as afterwards.
func tamperSnapshot(t *testing.T, store, hash, rel string) string {
	t.Helper()
	p := filepath.Join(SnapshotDir(store, hash), filepath.FromSlash(rel))
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, append(data, []byte("# edited in place\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := HashDir(SnapshotDir(store, hash))
	if err != nil {
		t.Fatal(err)
	}
	if got == hash {
		t.Fatal("the edit must change the hash, or the test proves nothing")
	}
	return got
}

func TestVerifyInstalledAcceptsAnIntactSnapshot(t *testing.T) {
	store := filepath.Join(t.TempDir(), "installed")
	hash := installByHand(t, store, sampleConfig(t))
	if err := VerifyInstalled(store, hash); err != nil {
		t.Fatalf("an intact snapshot must verify: %v", err)
	}
}

func TestVerifyInstalledMismatchNamesBothHashes(t *testing.T) {
	store := filepath.Join(t.TempDir(), "installed")
	hash := installByHand(t, store, sampleConfig(t))
	got := tamperSnapshot(t, store, hash, "agents/planner.yaml")
	err := VerifyInstalled(store, hash)
	if err == nil || err.Error() != mismatchText(hash, got) {
		t.Fatalf("got %v\nwant %s", err, mismatchText(hash, got))
	}
}

func TestVerifyInstalledMissingSnapshotWrapsTheRootError(t *testing.T) {
	store := filepath.Join(t.TempDir(), "installed")
	hash := installByHand(t, store, sampleConfig(t))
	if err := os.RemoveAll(SnapshotDir(store, hash)); err != nil {
		t.Fatal(err)
	}
	err := VerifyInstalled(store, hash)
	if err == nil || !strings.HasPrefix(err.Error(), "installed config "+hash+": config root ") || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a missing snapshot is the enumeration's own error, wrapped: %v", err)
	}
}

// TestVerifyInstalledIsTheFrozenCanon: the golden-vector directory, installed
// by hand under the name HashDir gives it, verifies — VerifyInstalled is
// HashDir over the snapshot and nothing else.
func TestVerifyInstalledIsTheFrozenCanon(t *testing.T) {
	store := filepath.Join(t.TempDir(), "installed")
	src := t.TempDir()
	writeCfg(t, src, "agents/a.yaml", "name: a\nmodel: m\n")
	writeCfg(t, src, "roles/r.yaml", "name: r\nworkflows: [w]\n")
	const golden = "sha256:3a2f6d0c0df4546527ad1ba5c5ae63cc803851f99614247fcbf38b16b4a5d885"
	if h := installByHand(t, store, src); h != golden {
		t.Fatalf("installed under %s, want the golden vector %s", h, golden)
	}
	if err := VerifyInstalled(store, golden); err != nil {
		t.Fatal(err)
	}
}

// TestLoadInstalledRefusesTamperedBytesBeforeParsing: one error, the exact
// mismatch text, installed with the pointer's hash — and a zero config,
// because bytes that do not match the pointer are never fed to the parser.
func TestLoadInstalledRefusesTamperedBytesBeforeParsing(t *testing.T) {
	store := filepath.Join(t.TempDir(), "installed")
	hash := installByHand(t, store, sampleConfig(t))
	got := tamperSnapshot(t, store, hash, "agents/planner.yaml")
	cfg, h, installed, errs := LoadInstalled(store)
	if !installed || h != hash || len(errs) != 1 || errs[0].Error() != mismatchText(hash, got) {
		t.Fatalf("installed=%v hash=%q errs=%v", installed, h, errs)
	}
	if len(cfg.Agents) != 0 || len(cfg.Roles) != 0 || len(cfg.Workflows) != 0 {
		t.Fatalf("tampered bytes must never be parsed: %+v", cfg)
	}
}

func TestLoadInstalledAddedFileIsAMismatch(t *testing.T) {
	store := filepath.Join(t.TempDir(), "installed")
	hash := installByHand(t, store, sampleConfig(t))
	writeCfg(t, SnapshotDir(store, hash), "roles/x.yaml", "name: x\nallowed_groups: [ops]\ncontrol: [apply]\n")
	got, err := HashDir(SnapshotDir(store, hash))
	if err != nil {
		t.Fatal(err)
	}
	cfg, _, installed, errs := LoadInstalled(store)
	if !installed || len(errs) != 1 || errs[0].Error() != mismatchText(hash, got) || len(cfg.Roles) != 0 {
		t.Fatalf("a file dropped into the snapshot is enumerated and therefore a mismatch: installed=%v errs=%v roles=%d", installed, errs, len(cfg.Roles))
	}
}

// TestLoadInstalledDeletedFileIsAMismatchNotALoadError: a snapshot that lost
// roles/ after install hashes differently, so the first (only) error is the
// mismatch — never "snapshot has no roles", which is the no-roles branch
// below.
func TestLoadInstalledDeletedFileIsAMismatchNotALoadError(t *testing.T) {
	store := filepath.Join(t.TempDir(), "installed")
	hash := installByHand(t, store, sampleConfig(t))
	if err := os.RemoveAll(filepath.Join(SnapshotDir(store, hash), "roles")); err != nil {
		t.Fatal(err)
	}
	got, err := HashDir(SnapshotDir(store, hash))
	if err != nil {
		t.Fatal(err)
	}
	_, _, installed, errs := LoadInstalled(store)
	if !installed || len(errs) != 1 || errs[0].Error() != mismatchText(hash, got) {
		t.Fatalf("installed=%v errs=%v", installed, errs)
	}
}

// TestLoadInstalledUnreadableFileIsTheHashStepsError: the hash step runs
// first, so an unreadable file surfaces as HashDir's error wrapped with the
// snapshot's name — observable proof of the order.
func TestLoadInstalledUnreadableFileIsTheHashStepsError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads mode-0 files")
	}
	store := filepath.Join(t.TempDir(), "installed")
	hash := installByHand(t, store, sampleConfig(t))
	p := filepath.Join(SnapshotDir(store, hash), "agents", "planner.yaml")
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, 0o600) })
	_, _, installed, errs := LoadInstalled(store)
	if !installed || len(errs) != 1 || !strings.HasPrefix(errs[0].Error(), "installed config "+hash+": hash config: agents/planner.yaml: ") || !errors.Is(errs[0], fs.ErrPermission) {
		t.Fatalf("installed=%v errs=%v", installed, errs)
	}
}

// TestInstalledRolesIsNotVerified pins the boundary: the roles-only
// authorization read does not verify the snapshot against the pointer (a
// snapshot whose agent files were edited still decides who may act), while
// the execution read of the same store refuses. A later change to this is
// deliberate, not accidental.
func TestInstalledRolesIsNotVerified(t *testing.T) {
	store := filepath.Join(t.TempDir(), "installed")
	hash := installByHand(t, store, sampleConfig(t))
	tamperSnapshot(t, store, hash, "agents/planner.yaml")
	roles, h, installed, err := InstalledRoles(store)
	if err != nil || !installed || h != hash || len(roles) != 2 {
		t.Fatalf("the lenient read must still yield roles: roles=%d hash=%q installed=%v err=%v", len(roles), h, installed, err)
	}
	if _, _, _, errs := LoadInstalled(store); len(errs) != 1 {
		t.Fatalf("the execution read of the same store must refuse: %v", errs)
	}
}

// TestLoadInstalledFailsClosedOnSnapshotWithNoRoles: the no-roles branch is
// defense in depth. It is reachable only through a hand-built, correctly
// hashed, role-less <hex>/ that a filesystem writer re-points current at —
// a snapshot that LOST roles/ after install hashes differently and is the
// mismatch case (TestLoadInstalledDeletedFileIsAMismatchNotALoadError). Here
// roles/ is removed from the source BEFORE hashing, so the snapshot hashes
// to its name and genuinely holds no roles; every installed snapshot passed
// the no-apply-floor, so this is damage and fails closed naming the snapshot.
func TestLoadInstalledFailsClosedOnSnapshotWithNoRoles(t *testing.T) {
	store := filepath.Join(t.TempDir(), "installed")
	src := sampleConfig(t)
	if err := os.RemoveAll(filepath.Join(src, "roles")); err != nil {
		t.Fatal(err)
	}
	hash := installByHand(t, store, src)
	_, _, installed, errs := LoadInstalled(store)
	if !installed || len(errs) != 1 || errs[0].Error() != "installed config "+hash+": snapshot has no roles" {
		t.Fatalf("installed=%v errs=%v", installed, errs)
	}
}

func TestSnapshotDirStripsTheTypedPrefix(t *testing.T) {
	if got := SnapshotDir("/s", "sha256:abc"); got != filepath.Join("/s", "abc") {
		t.Fatalf("got %q", got)
	}
}

// TestStageFilesWritesExactlyTheKeys is StageSnapshot's twin for an
// in-memory proposal: every key lands under a fresh .staging-* temp
// directly under the store, mode 0600, and the staged copy hashes as the
// proposal.
func TestStageFilesWritesExactlyTheKeys(t *testing.T) {
	store := filepath.Join(t.TempDir(), "installed")
	m := map[string][]byte{
		"agents/planner.yaml": []byte("name: planner\n"),
		"roles/.x.yaml":       []byte("name: dot\n"),
		"gateway.yaml":        []byte("models: {}\n"),
	}
	temp, err := StageFiles(store, m)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(filepath.Base(temp), ".staging-") || filepath.Dir(temp) != store {
		t.Fatalf("temp must be a .staging-* dir directly under the store: %s", temp)
	}
	for rel, want := range m {
		p := filepath.Join(temp, filepath.FromSlash(rel))
		got, err := os.ReadFile(p)
		if err != nil || string(got) != string(want) {
			t.Fatalf("%s: got %q err=%v", rel, got, err)
		}
		info, _ := os.Stat(p)
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: mode %v, want 0600", rel, info.Mode().Perm())
		}
	}
	want, _ := HashFiles(m)
	if got, err := HashDir(temp); err != nil || got != want {
		t.Fatalf("HashDir(temp)=%q err=%v, want %q", got, err, want)
	}
	if _, installed, err := InstalledHash(store); installed || err != nil {
		t.Fatalf("staging must not install: installed=%v err=%v", installed, err)
	}
}

func TestStageFilesRejectsInvalidKeyLeavingNothing(t *testing.T) {
	store := filepath.Join(t.TempDir(), "installed")
	_, err := StageFiles(store, map[string][]byte{"roles/r.yaml": []byte("ok"), "../escape.yaml": []byte("no")})
	if err == nil {
		t.Fatal("an invalid key must fail the whole stage")
	}
	if strings.Contains(err.Error(), "escape") {
		t.Fatalf("the key is attacker-controlled and must not be echoed: %v", err)
	}
	if ents, _ := os.ReadDir(store); len(ents) != 0 {
		t.Fatalf("nothing may remain under the store: %v", ents)
	}
}

func TestStageFilesUnwritableStoreLeavesNoTemp(t *testing.T) {
	store := filepath.Join(t.TempDir(), "installed")
	if err := os.WriteFile(store, []byte("in the way"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := StageFiles(store, map[string][]byte{"roles/r.yaml": []byte("x")}); err == nil {
		t.Fatal("a store that is a file must fail")
	}
}

// TestStageFilesCaseVariantPairNeverSilentlyOverwrites: two keys the
// filesystem may consider one name. On a case-insensitive volume (the
// developer's APFS) the second O_EXCL create fails loud and nothing is left
// behind; on a case-sensitive one (CI's ext4) both are staged and the canon
// agrees. Either outcome is correct; a silent overwrite is the bug.
func TestStageFilesCaseVariantPairNeverSilentlyOverwrites(t *testing.T) {
	store := filepath.Join(t.TempDir(), "installed")
	m := map[string][]byte{"agents/X.yaml": []byte("name: X\n"), "agents/x.yaml": []byte("name: x\n")}
	temp, err := StageFiles(store, m)
	if err != nil {
		// bundleOrder writes agents/X.yaml first, so agents/x.yaml is the one that collides.
		if !strings.Contains(err.Error(), "agents/x.yaml") || !errors.Is(err, fs.ErrExist) {
			t.Fatalf("the colliding key must be named and the cause be ErrExist: %v", err)
		}
		if ents, _ := os.ReadDir(store); len(ents) != 0 {
			t.Fatalf("nothing may remain under the store after a failed stage: %v", ents)
		}
		return
	}
	want, _ := HashFiles(m)
	if got, err := HashDir(temp); err != nil || got != want {
		t.Fatalf("case-sensitive volume: HashDir(temp)=%q err=%v, want %q", got, err, want)
	}
}
