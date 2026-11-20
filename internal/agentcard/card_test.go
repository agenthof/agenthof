package agentcard

import (
	"strings"
	"testing"
)

func TestParseRejectsNonASCIIKeys(t *testing.T) {
	// "toolſ" folds to "tools" under encoding/json's matching but not under
	// strings.ToLower, so any non-ASCII key is refused outright.
	for _, in := range []string{
		`{"name":"a","tools":1,"toolſ":2}`,
		`{"name":"a","K":1}`,
		`{"nämé":"a"}`,
	} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Fatalf("accepted non-ASCII key in %s", in)
		}
	}
}

const cardJSON = `{
  "name": "Triage Bot",
  "description": "triages tickets",
  "version": "1.2.0",
  "capabilities": {"extensions": [
    {"uri": "https://example.com/other", "params": {"x": 1}},
    {"uri": "https://agenthof.dev/ext/agent/v1", "params": {
      "artifact": "ghcr.io/acme/triage@sha256:abc",
      "interface": "a2a",
      "tools": [{"resource": "tickets", "tools": ["get"], "mode": "read-only"}],
      "model": "fast"
    }}
  ]},
  "signatures": [{"protected": "e30", "signature": "c2ln"}]
}`

func TestParseCardExtension(t *testing.T) {
	c, err := Parse([]byte(cardJSON))
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "Triage Bot" || c.Version != "1.2.0" || len(c.Signatures) != 1 {
		t.Fatalf("unexpected card: %+v", c)
	}
	if string(c.Raw()) != cardJSON {
		t.Fatal("raw bytes not preserved")
	}
	ext, err := c.Extension()
	if err != nil {
		t.Fatal(err)
	}
	if ext.Artifact != "ghcr.io/acme/triage@sha256:abc" || ext.Model != "fast" ||
		len(ext.Tools) != 1 || ext.Tools[0].Resource != "tickets" {
		t.Fatalf("unexpected ext: %+v", ext)
	}

	if _, err := Parse([]byte(`{"name":"a","name":"b"}`)); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate top-level key: %v", err)
	}
	if _, err := Parse([]byte(`{"capabilities":{"extensions":[{"uri":"u","uri":"v"}]}}`)); err == nil {
		t.Fatal("nested duplicate key accepted")
	}
	if _, err := Parse([]byte(`{} {}`)); err == nil {
		t.Fatal("trailing data accepted")
	}
	big := `{"name":"` + strings.Repeat("a", MaxCardBytes) + `"}`
	if _, err := Parse([]byte(big)); err == nil {
		t.Fatal("oversized card accepted")
	}
}

func TestExtensionRequiresExactlyOne(t *testing.T) {
	for name, in := range map[string]string{
		"none": `{"capabilities":{"extensions":[]}}`,
		"two": `{"capabilities":{"extensions":[
			{"uri":"https://agenthof.dev/ext/agent/v1","params":{"artifact":"a@sha256:1"}},
			{"uri":"https://agenthof.dev/ext/agent/v1","params":{"artifact":"b@sha256:2"}}]}}`,
		"unknown field": `{"capabilities":{"extensions":[{"uri":"https://agenthof.dev/ext/agent/v1","params":{"artifact":"a","bogus":1}}]}}`,
		"no artifact":   `{"capabilities":{"extensions":[{"uri":"https://agenthof.dev/ext/agent/v1","params":{}}]}}`,
	} {
		c, err := Parse([]byte(in))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := c.Extension(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestParseRejectsCaseVariantKeys(t *testing.T) {
	for name, in := range map[string]string{
		"top level": `{"name":"a","Name":"b"}`,
		"params":    `{"capabilities":{"extensions":[{"uri":"https://agenthof.dev/ext/agent/v1","params":{"artifact":"good@sha256:1","Artifact":"evil@sha256:2"}}]}}`,
	} {
		if _, err := Parse([]byte(in)); err == nil || !strings.Contains(err.Error(), "duplicate") {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestParseRejectsDeepNesting(t *testing.T) {
	deep := strings.Repeat("[", 100) + strings.Repeat("]", 100)
	if _, err := Parse([]byte(`{"x":` + deep + `}`)); err == nil || !strings.Contains(err.Error(), "deeper") {
		t.Fatalf("got %v", err)
	}
}

const (
	hashA = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	hashB = "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
)

func extCard(params string) string {
	return `{"capabilities":{"extensions":[{"uri":"https://agenthof.dev/ext/agent/v1","params":` + params + `}]}}`
}

func TestExtensionHostProgramForm(t *testing.T) {
	hp := `"host-program":{"program":"triage-bot","builds":[{"os":"darwin","arch":"arm64","sha256":"` + hashA + `"},{"os":"darwin","arch":"amd64","sha256":"` + hashB + `"}]}`
	for name, tc := range map[string]struct {
		params   string
		wantOCI  string
		wantHost bool
	}{
		"host-program only": {`{` + hp + `}`, "", true},
		"both forms":        {`{"artifact":"ghcr.io/acme/t@sha256:abc",` + hp + `}`, "ghcr.io/acme/t@sha256:abc", true},
		"oci only":          {`{"artifact":"ghcr.io/acme/t@sha256:abc"}`, "ghcr.io/acme/t@sha256:abc", false},
	} {
		c, err := Parse([]byte(extCard(tc.params)))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		ext, err := c.Extension()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if ext.Artifact != tc.wantOCI || (ext.HostProgram != nil) != tc.wantHost {
			t.Fatalf("%s: unexpected ext: %+v", name, ext)
		}
		if tc.wantHost {
			h := ext.HostProgram
			if h.Program != "triage-bot" || len(h.Builds) != 2 ||
				h.Builds[0].OS != "darwin" || h.Builds[0].Arch != "arm64" || h.Builds[0].SHA256 != hashA {
				t.Fatalf("%s: unexpected host-program: %+v", name, h)
			}
		}
	}
}

func TestExtensionRequiresAnArtifactForm(t *testing.T) {
	c, err := Parse([]byte(extCard(`{"interface":"a2a"}`)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Extension(); err == nil || !strings.Contains(err.Error(), "at least one artifact") {
		t.Fatalf("got %v", err)
	}
}

func TestExtensionRejectsMalformedHostProgram(t *testing.T) {
	build := func(h string) string {
		return `{"host-program":{"program":"p","builds":[{"os":"darwin","arch":"arm64","sha256":"` + h + `"}]}}`
	}
	upper := "sha256:" + strings.Repeat("A", 64)
	for name, params := range map[string]string{
		"empty object":      `{"host-program":{}}`,
		"no program":        `{"host-program":{"builds":[{"os":"darwin","arch":"arm64","sha256":"` + hashA + `"}]}}`,
		"no builds":         `{"host-program":{"program":"p"}}`,
		"empty builds":      `{"host-program":{"program":"p","builds":[]}}`,
		"no prefix":         build(strings.TrimPrefix(hashA, "sha256:")),
		"short":             build("sha256:abc"),
		"long":              build(hashA + "0"),
		"uppercase hex":     build(upper),
		"non-hex":           build("sha256:" + strings.Repeat("g", 64)),
		"empty hash":        build(""),
		"wrong algorithm":   build("sha512:" + strings.Repeat("a", 64)),
		"missing os":        `{"host-program":{"program":"p","builds":[{"arch":"arm64","sha256":"` + hashA + `"}]}}`,
		"missing arch":      `{"host-program":{"program":"p","builds":[{"os":"darwin","sha256":"` + hashA + `"}]}}`,
		"unknown field":     `{"host-program":{"program":"p","bogus":1,"builds":[{"os":"darwin","arch":"arm64","sha256":"` + hashA + `"}]}}`,
		"unknown build key": `{"host-program":{"program":"p","builds":[{"os":"darwin","arch":"arm64","sha256":"` + hashA + `","x":1}]}}`,
	} {
		c, err := Parse([]byte(extCard(params)))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := c.Extension(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	// A malformed host-program is refused even when a valid OCI form is present.
	c, err := Parse([]byte(extCard(`{"artifact":"a@sha256:1","host-program":{"program":"p","builds":[{"os":"darwin","arch":"arm64","sha256":"sha256:abc"}]}}`)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Extension(); err == nil {
		t.Error("malformed host-program accepted alongside a valid artifact")
	}
}

func TestParseRejectsHostProgramKeyVariants(t *testing.T) {
	b := `{"os":"darwin","arch":"arm64","sha256":"` + hashA + `"}`
	for name, params := range map[string]string{
		"case-variant form": `{"host-program":{"program":"a","builds":[` + b + `]},"Host-Program":{"program":"evil","builds":[` + b + `]}}`,
		"duplicate program": `{"host-program":{"program":"a","program":"evil","builds":[` + b + `]}}`,
		"case-variant hash": `{"host-program":{"program":"a","builds":[{"os":"darwin","arch":"arm64","sha256":"` + hashA + `","SHA256":"` + hashB + `"}]}}`,
		"non-ASCII key":     `{"host-program":{"prógram":"a","builds":[` + b + `]}}`,
	} {
		if _, err := Parse([]byte(extCard(params))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
