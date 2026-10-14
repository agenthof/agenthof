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
