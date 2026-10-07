package config

import (
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
