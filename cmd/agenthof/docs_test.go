package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestConfigReferenceDocumentsInvestigateAnchors fails when
// docs/reference/config.md stops naming what investigate shows about
// anchors: the flag in the flags table, the text trailer, the verdict
// vocabulary, and the rule that a verdict never changes the exit code.
// A change to any of them forces the docs update in the same change.
func TestConfigReferenceDocumentsInvestigateAnchors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "reference", "config.md"))
	if err != nil {
		t.Fatalf("config reference missing: %v", err)
	}
	doc := string(data)
	row := ""
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(line, "| `agenthof investigate ") {
			row = line
		}
	}
	if row == "" || !strings.Contains(row, "[--anchor-key <path>]") || !strings.Contains(row, "`--anchor-key`") {
		t.Fatalf("the investigate flags row must list --anchor-key: %q", row)
	}
	for _, want := range []string{
		"anchors: N (a verified, b mismatch, c unverifiable)",
		"`verified`, `mismatch` or `unverifiable`",
		"never changes the exit code or `integrity.ok`",
		"`proof` is never in the document",
		"`.events[].anchor.verdict`",
		"the server pins `anchor.pub` beside its own ledger",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("docs/reference/config.md must say %q", want)
		}
	}
	// "worm" in lower case is a reserved integrity.yaml sink value the
	// reference already names; the banned claims are the three below.
	for _, banned := range []string{"tamper-proof", "immutable", "write-once"} {
		if strings.Contains(doc, banned) {
			t.Fatalf("docs/reference/config.md must not say %q", banned)
		}
	}
}

// TestConfigReferenceDocumentsSeal fails when docs/reference/config.md stops
// documenting sealing: the audit seal row with --if-larger-than, the segment
// and manifest names and that they never end in .jsonl, the standing
// older-binary rule, nine control operations with seal among them, the
// verify exit 8 row, the banned words absent and "self-contained" absent from
// the segment wording; docs/concepts.md no longer says nothing seals the log.
func TestConfigReferenceDocumentsSeal(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "reference", "config.md"))
	if err != nil {
		t.Fatalf("config reference missing: %v", err)
	}
	doc := string(data)
	flat := strings.Join(strings.Fields(doc), " ")
	row := ""
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(line, "| `agenthof audit seal ") {
			row = line
		}
	}
	if row == "" || !strings.Contains(row, "[--if-larger-than <size>]") || !strings.Contains(row, "`--if-larger-than`") {
		t.Fatalf("the audit seal row must list --if-larger-than: %q", row)
	}
	for _, want := range []string{
		"`control.jsonl.seg-",
		"`control.jsonl.segments`",
		"never ends in `.jsonl`",
		"upgrade every binary that shares the control root before the first seal, and never run an older one against it afterwards",
		"`anchor`, `seal` — the nine fixed operations",
		"| `8` | **Rotation not completed**",
		"rotation_incomplete",
		"`broken` covers a set fault",
	} {
		if !strings.Contains(flat, strings.Join(strings.Fields(want), " ")) {
			t.Fatalf("docs/reference/config.md must say %q", want)
		}
	}
	if strings.Contains(flat, "the eight fixed operations") {
		t.Fatal("eight → nine")
	}
	for _, banned := range []string{"tamper-proof", "immutable", "write-once", "self-contained"} {
		if strings.Contains(doc, banned) {
			t.Fatalf("docs/reference/config.md must not say %q", banned)
		}
	}
	concepts, err := os.ReadFile(filepath.Join("..", "..", "docs", "concepts.md"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(concepts), "Nothing rotates or seals the control log today") {
		t.Fatal("docs/concepts.md must no longer say nothing seals the control log")
	}
}
