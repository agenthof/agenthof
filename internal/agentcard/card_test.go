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
