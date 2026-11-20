package registry

import (
	"strings"
	"testing"

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
