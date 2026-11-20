package registry

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/agenthof/agenthof/internal/config"
)

func TestValidateProvenanceForms(t *testing.T) {
	d := "sha256:" + strings.Repeat("a", 64)
	okBuild := config.HostBuild{OS: "linux", Arch: "amd64", SHA256: d}
	img := "r.example/a@sha256:" + strings.Repeat("a", 64)
	cases := []struct {
		name string
		prov config.Provenance
		bad  bool
	}{
		{"empty", config.Provenance{}, true},
		{"tag-only image", config.Provenance{Image: "r.example/a:latest"}, true},
		{"image digest uppercase", config.Provenance{Image: "r.example/a@sha256:" + strings.Repeat("A", 64)}, true},
		{"image digest short", config.Provenance{Image: "r.example/a@sha256:abc"}, true},
		{"program without builds", config.Provenance{Program: "p"}, true},
		{"builds without program", config.Provenance{Builds: []config.HostBuild{okBuild}}, true},
		{"build missing os", config.Provenance{Program: "p", Builds: []config.HostBuild{{Arch: "amd64", SHA256: d}}}, true},
		{"build missing arch", config.Provenance{Program: "p", Builds: []config.HostBuild{{OS: "linux", SHA256: d}}}, true},
		{"build bad hash", config.Provenance{Program: "p", Builds: []config.HostBuild{{OS: "linux", Arch: "amd64", SHA256: strings.Repeat("a", 64)}}}, true},
		{"one bad build among good", config.Provenance{Program: "p", Builds: []config.HostBuild{okBuild, {OS: "linux", Arch: "arm64"}}}, true},
		{"oci only", config.Provenance{Image: img}, false},
		{"program only", config.Provenance{Program: "p", Builds: []config.HostBuild{okBuild}}, false},
		{"both forms", config.Provenance{Image: img, Program: "p", Builds: []config.HostBuild{okBuild}}, false},
		// Each form is judged independently: one well-formed form suffices, so a
		// valid image passes even beside a malformed host-program form. Intended;
		// run-time enforcement verifies the form it actually uses.
		{"valid image beside malformed program", config.Provenance{Image: img, Program: "p", Builds: []config.HostBuild{{OS: "linux", Arch: "amd64", SHA256: "bad"}}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseCfg()
			p := tc.prov
			cfg.Agents[0].Provenance = &p
			cfg.Agents[0].Endpoint = ""
			if !cfg.Agents[0].SpawnOnly() {
				t.Fatal("provenance present must be SpawnOnly")
			}
			c := codes(Validate(cfg))
			if tc.bad && c["bad-provenance"] != 1 {
				t.Fatalf("want one bad-provenance, got %v", c)
			}
			if !tc.bad && len(c) != 0 {
				t.Fatalf("want valid, got %v", c)
			}
		})
	}
}

func TestProvenanceYAMLOmitEmpty(t *testing.T) {
	d := "sha256:" + strings.Repeat("a", 64)
	out, err := yaml.Marshal(config.Provenance{Program: "p", Builds: []config.HostBuild{{OS: "linux", Arch: "amd64", SHA256: d}}, CardSHA256: "c", CardVersion: "1"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "image:") {
		t.Fatalf("empty image must be omitted:\n%s", out)
	}
	var back config.Provenance
	if err := yaml.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	if back.Program != "p" || len(back.Builds) != 1 || back.Builds[0].SHA256 != d || !back.HasWellFormedForm() {
		t.Fatalf("round trip lost data: %+v", back)
	}
	out, err = yaml.Marshal(config.Provenance{Image: "r@" + d})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "program:") || strings.Contains(string(out), "builds:") {
		t.Fatalf("empty program/builds must be omitted:\n%s", out)
	}
}
