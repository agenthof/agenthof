package main

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/refspawn"
	"github.com/agenthof/agenthof/internal/rungateway"
)

const (
	imgDigest   = "sha256:" + "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11"
	otherDigest = "sha256:" + "bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22"
	archDigest  = "sha256:" + "cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33"
	progHash    = "sha256:" + "dd44dd44dd44dd44dd44dd44dd44dd44dd44dd44dd44dd44dd44dd44dd44dd44"
	otherHash   = "sha256:" + "ee55ee55ee55ee55ee55ee55ee55ee55ee55ee55ee55ee55ee55ee55ee55ee55"
)

// recordingProvisioner is a stubProvisioner that also remembers what it was
// asked to enforce.
type recordingProvisioner struct {
	stubProvisioner
	mu2      sync.Mutex
	expected map[string][]refspawn.ExpectedArtifact // a deep copy, taken before any mutation
	// poison rewrites the received expectation in place to bogus (a lenient
	// or lying supervisor's view of what was consented).
	poison string
}

func (r *recordingProvisioner) Provision(ctx context.Context, id string, agents []string, exp map[string][]refspawn.ExpectedArtifact) (*refspawn.Lease, error) {
	r.mu2.Lock()
	r.expected = map[string][]refspawn.ExpectedArtifact{}
	for a, forms := range exp {
		for _, f := range forms {
			r.expected[a] = append(r.expected[a], refspawn.ExpectedArtifact{Kind: f.Kind, Values: append([]string(nil), f.Values...)})
		}
	}
	r.mu2.Unlock()
	if r.poison != "" {
		for _, forms := range exp {
			for i := range forms {
				forms[i].Values = []string{r.poison}
			}
		}
	}
	return r.stubProvisioner.Provision(ctx, id, agents, exp)
}

func admissionConfig() config.Config {
	cfg := spawnTestConfig()
	prov := &config.Provenance{Image: "registry.test/enrolled@" + imgDigest, Program: "enrolled",
		Builds: []config.HostBuild{{OS: "darwin", Arch: "arm64", SHA256: progHash}}, CardSHA256: imgDigest, CardVersion: "1"}
	cfg.Agents = append(cfg.Agents,
		config.AgentDef{Name: "enrolled", SourceFile: "a", Provenance: prov},
		config.AgentDef{Name: "enrolled2", SourceFile: "a", Provenance: &config.Provenance{Image: "registry.test/second@" + otherDigest, CardSHA256: imgDigest, CardVersion: "1"}},
		config.AgentDef{Name: "imgonly", SourceFile: "a", Provenance: &config.Provenance{Image: "registry.test/imgonly@" + imgDigest, CardSHA256: imgDigest, CardVersion: "1"}},
		config.AgentDef{Name: "progonly", SourceFile: "a", Provenance: &config.Provenance{Program: "progonly",
			Builds: []config.HostBuild{{OS: "darwin", Arch: "arm64", SHA256: progHash}}, CardSHA256: imgDigest, CardVersion: "1"}},
	)
	extra := map[string]string{"two-enrolled-wf": "", "imgonly-wf": "imgonly", "progonly-wf": "progonly"}
	for wf, agent := range extra {
		steps := []config.Step{{Name: "s", Agent: agent}}
		if agent == "" {
			steps = []config.Step{{Name: "a", Agent: "enrolled"}, {Name: "b", Agent: "enrolled2"}}
		}
		cfg.Workflows = append(cfg.Workflows, config.WorkflowDef{Name: wf, SourceFile: "w", Steps: steps})
		cfg.Agents[0].MaySpawn = append(cfg.Agents[0].MaySpawn, config.SpawnTarget{Role: "worker", Workflow: wf})
		for i := range cfg.Roles {
			if cfg.Roles[i].Name == "worker" {
				cfg.Roles[i].Workflows = append(cfg.Roles[i].Workflows, wf)
			}
		}
	}
	cfg.Agents[0].MaySpawn = append(cfg.Agents[0].MaySpawn,
		config.SpawnTarget{Role: "worker", Workflow: "enrolled-wf"}, config.SpawnTarget{Role: "worker", Workflow: "mixed-wf"})
	cfg.Workflows = append(cfg.Workflows,
		config.WorkflowDef{Name: "enrolled-wf", SourceFile: "w", Steps: []config.Step{{Name: "s", Agent: "enrolled"}}},
		config.WorkflowDef{Name: "mixed-wf", SourceFile: "w", Steps: []config.Step{{Name: "a", Agent: "child"}, {Name: "b", Agent: "enrolled"}}},
	)
	for i := range cfg.Roles {
		if cfg.Roles[i].Name == "worker" {
			cfg.Roles[i].Workflows = append(cfg.Roles[i].Workflows, "enrolled-wf", "mixed-wf")
		}
	}
	return cfg
}

// admissionLease builds a lease whose per-agent measured artifact is ran.
func admissionLease(t *testing.T, agents []string, ran map[string]refspawn.RanArtifact) *refspawn.Lease {
	t.Helper()
	dir := shortDir(t)
	childDir, execDir := filepath.Join(dir, "r-x"), filepath.Join(dir, "r-x-exec")
	for _, d := range []string{childDir, execDir} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	socks := map[string]string{}
	for _, a := range agents {
		socks[a] = filepath.Join(childDir, a+".sock")
	}
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	return refspawn.NewLease(childDir, socks, filepath.Join(execDir, "refexec.sock"), "podman", nil, ran, pr)
}

func spawnWith(t *testing.T, workflow string, agents []string, ran map[string]refspawn.RanArtifact) (rungateway.SpawnResult, *recordingProvisioner, string) {
	t.Helper()
	stub := &recordingProvisioner{stubProvisioner: stubProvisioner{lease: admissionLease(t, agents, ran)}}
	runs := t.TempDir()
	deps := buildDeps(t, admissionConfig(), runs, stub)
	res, err := deps.Spawn(context.Background(), "worker", workflow, "x", parentBinding())
	if err != nil {
		t.Fatal(err)
	}
	return res, stub, runs + "/runs"
}

// notDriven asserts the child was refused for the admission reason and was
// never driven: no run id was minted and nothing was written to the run log.
func notDriven(t *testing.T, res rungateway.SpawnResult, runsDir string) {
	t.Helper()
	if res.Status != "refused" || res.Reason != reasonArtifactNotConsented {
		t.Fatalf("res=%+v, want refused with the admission reason", res)
	}
	if res.Reason == reasonCompartmentUnavailable || res.Reason == reasonArtifactRefused {
		t.Fatal("the admission reason must be distinct")
	}
	if !res.Provisioned {
		t.Fatal("the refusal must count against max_total_spawns (Provisioned)")
	}
	if res.ChildRunID != "" {
		t.Fatalf("a refused child must never be driven, got run %q", res.ChildRunID)
	}
	ents, err := os.ReadDir(runsDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("cannot inspect the run log dir: %v", err) // never pass vacuously
	}
	if len(ents) != 0 {
		t.Fatalf("a refused child must write no run: %v", ents)
	}
}

func driven(t *testing.T, res rungateway.SpawnResult) {
	t.Helper()
	if res.Reason == reasonArtifactNotConsented || res.ChildRunID == "" || !res.Provisioned {
		t.Fatalf("res=%+v, want the child admitted and driven", res)
	}
}

func TestAdmissionRanInConsentedSetAdmits(t *testing.T) {
	for name, ran := range map[string]refspawn.RanArtifact{
		"image":   {Kind: "oci-image", Values: []string{imgDigest}},
		"program": {Kind: "host-program", Values: []string{progHash}},
	} {
		t.Run(name, func(t *testing.T) {
			res, _, _ := spawnWith(t, "enrolled-wf", []string{"enrolled"}, map[string]refspawn.RanArtifact{"enrolled": ran})
			driven(t, res)
		})
	}
}

func TestAdmissionAbsentRanRefuses(t *testing.T) {
	res, stub, runs := spawnWith(t, "enrolled-wf", []string{"enrolled"}, nil)
	notDriven(t, res, runs)
	// The refusal releases the lease: its held body is closed, so Done fires.
	select {
	case <-stub.lease.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the lease was not released on refusal")
	}
	if len(res.ChildArtifact) != 0 {
		t.Fatalf("nothing was measured, so no evidence: %v", res.ChildArtifact)
	}
}

func TestAdmissionRanNotConsentedRefuses(t *testing.T) {
	cases := map[string]refspawn.RanArtifact{
		"wrong image digest":      {Kind: "oci-image", Values: []string{otherDigest}},
		"wrong program hash":      {Kind: "host-program", Values: []string{otherHash}},
		"right value, wrong kind": {Kind: "host-program", Values: []string{imgDigest}},
		"empty values":            {Kind: "oci-image", Values: nil},
		"unknown kind":            {Kind: "mystery", Values: []string{imgDigest}},
	}
	for name, ran := range cases {
		t.Run(name, func(t *testing.T) {
			res, _, runs := spawnWith(t, "enrolled-wf", []string{"enrolled"}, map[string]refspawn.RanArtifact{"enrolled": ran})
			notDriven(t, res, runs)
			// (g) the mismatching measurement is the evidence.
			if got := res.ChildArtifact["enrolled"]; got.Kind != ran.Kind || !reflect.DeepEqual(got.Values, ran.Values) {
				t.Fatalf("evidence = %+v, want the measured %+v", res.ChildArtifact, ran)
			}
		})
	}
}

func TestAdmissionMultiArchSetAdmitsWhenConsentedDigestIsAMember(t *testing.T) {
	ran := refspawn.RanArtifact{Kind: "oci-image", Values: []string{archDigest, imgDigest, otherDigest}}
	res, _, _ := spawnWith(t, "enrolled-wf", []string{"enrolled"}, map[string]refspawn.RanArtifact{"enrolled": ran})
	driven(t, res)
	// And a multi-member set that does NOT contain it is refused.
	bad := refspawn.RanArtifact{Kind: "oci-image", Values: []string{archDigest, otherDigest}}
	res, _, runs := spawnWith(t, "enrolled-wf", []string{"enrolled"}, map[string]refspawn.RanArtifact{"enrolled": bad})
	notDriven(t, res, runs)
}

func TestAdmissionMixedSetRefusesWhole(t *testing.T) {
	ran := map[string]refspawn.RanArtifact{"enrolled": {Kind: "oci-image", Values: []string{otherDigest}}}
	res, _, runs := spawnWith(t, "mixed-wf", []string{"child", "enrolled"}, ran)
	notDriven(t, res, runs)
	if _, ok := res.ChildArtifact["child"]; ok {
		t.Fatalf("a non-provenance agent is not evidence: %v", res.ChildArtifact)
	}
}

func TestAdmissionNonProvenanceUnchanged(t *testing.T) {
	// No ran at all, no expected sent: a plain child is admitted and driven.
	res, stub, _ := spawnWith(t, "child-wf", []string{"child"}, nil)
	driven(t, res)
	if len(stub.expected) != 0 {
		t.Fatalf("a non-provenance set sends no expectation, got %v", stub.expected)
	}
}

// The discriminating test: the supervisor's received expectation is rewritten
// to otherDigest and the lease reports ran == otherDigest. A check that
// compared ran against what was sent would admit; reading provenance fresh
// from the registry refuses.
func TestAdmissionComparesAgainstFreshProvenanceNotTheSentMap(t *testing.T) {
	stub := &recordingProvisioner{poison: otherDigest, stubProvisioner: stubProvisioner{lease: admissionLease(t, []string{"enrolled"},
		map[string]refspawn.RanArtifact{"enrolled": {Kind: "oci-image", Values: []string{otherDigest}}})}}
	runs := t.TempDir()
	deps := buildDeps(t, admissionConfig(), runs, stub)
	res, err := deps.Spawn(context.Background(), "worker", "enrolled-wf", "x", parentBinding())
	if err != nil {
		t.Fatal(err)
	}
	notDriven(t, res, runs+"/runs")
}

func TestAdmissionSingleFormConsentRefusesOtherKind(t *testing.T) {
	cases := map[string]struct {
		wf, agent string
		ran       refspawn.RanArtifact
	}{
		"image-only consent, host-program ran": {"imgonly-wf", "imgonly", refspawn.RanArtifact{Kind: "host-program", Values: []string{imgDigest, progHash}}},
		"program-only consent, oci-image ran":  {"progonly-wf", "progonly", refspawn.RanArtifact{Kind: "oci-image", Values: []string{imgDigest, progHash}}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			res, _, runs := spawnWith(t, c.wf, []string{c.agent}, map[string]refspawn.RanArtifact{c.agent: c.ran})
			notDriven(t, res, runs)
		})
	}
	// Positive controls: each single form is admitted by its own kind.
	res, _, _ := spawnWith(t, "imgonly-wf", []string{"imgonly"}, map[string]refspawn.RanArtifact{"imgonly": {Kind: "oci-image", Values: []string{imgDigest}}})
	driven(t, res)
	res, _, _ = spawnWith(t, "progonly-wf", []string{"progonly"}, map[string]refspawn.RanArtifact{"progonly": {Kind: "host-program", Values: []string{progHash}}})
	driven(t, res)
}

func TestAdmissionTwoEnrolledOneMismatchRefusesWhole(t *testing.T) {
	ran := map[string]refspawn.RanArtifact{
		"enrolled":  {Kind: "oci-image", Values: []string{imgDigest}},  // matches
		"enrolled2": {Kind: "oci-image", Values: []string{archDigest}}, // does not
	}
	res, _, runs := spawnWith(t, "two-enrolled-wf", []string{"enrolled", "enrolled2"}, ran)
	notDriven(t, res, runs)
	if _, ok := res.ChildArtifact["enrolled2"]; !ok || len(res.ChildArtifact) != 1 {
		t.Fatalf("evidence must be the mismatching agent only: %v", res.ChildArtifact)
	}
}

func TestConsentedFormsIgnoreMalformedValues(t *testing.T) {
	def := config.AgentDef{Name: "x", Provenance: &config.Provenance{Program: "p",
		Builds: []config.HostBuild{{OS: "a", Arch: "b", SHA256: ""}, {OS: "a", Arch: "c", SHA256: "sha256:zz"}}}}
	if forms := consentedForms(def); len(forms) != 0 {
		t.Fatalf("malformed consented values must yield no form, got %+v", forms)
	}
	if ranConsented("host-program", []string{""}, consentedForms(def)) {
		t.Fatal("an empty ran must never match an empty consented value")
	}
}

func TestAdmissionReadsProvenanceFreshNotFromWhatWasSent(t *testing.T) {
	// The supervisor is sent the expectation, but the check must not depend
	// on it: a lease that reports nothing is refused regardless.
	res, stub, runs := spawnWith(t, "enrolled-wf", []string{"enrolled"}, nil)
	notDriven(t, res, runs)
	want := map[string][]refspawn.ExpectedArtifact{"enrolled": {
		{Kind: "oci-image", Values: []string{imgDigest}},
		{Kind: "host-program", Values: []string{progHash}},
	}}
	if !reflect.DeepEqual(stub.expected, want) {
		t.Fatalf("sent = %+v, want digest-only forms %+v", stub.expected, want)
	}
	for _, f := range stub.expected["enrolled"] {
		for _, v := range f.Values {
			if strings.Contains(v, "@") || strings.Contains(v, "registry.test") {
				t.Fatalf("expected value %q must be the digest only", v)
			}
		}
	}
}
