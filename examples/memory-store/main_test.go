package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// callWith runs the named tool's handler with the given limits and returns
// whether it failed and the first text content.
func callWith(t *testing.T, be Backend, l Limits, tool, args string) (bool, string) {
	t.Helper()
	var h mcp.ToolHandler
	if tool == "memory_upsert" {
		h = upsertHandler(be, l)
	} else {
		h = searchHandler(be, l)
	}
	res, err := h(context.Background(), &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: tool, Arguments: json.RawMessage(args)}})
	if err != nil {
		t.Fatal(err)
	}
	text := ""
	if len(res.Content) > 0 {
		if tc, ok := res.Content[0].(*mcp.TextContent); ok {
			text = tc.Text
		}
	}
	return res.IsError, text
}

func TestBackendSelection(t *testing.T) {
	dir := t.TempDir()
	c, err := parseConfig([]string{"-backend", "embedded", "-store-file", dir + "/s.json"}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.backend.(*embeddedBackend); !ok {
		t.Fatalf("embedded: got %T", c.backend)
	}
	c, err = parseConfig([]string{"-backend", "qdrant", "-qdrant-url", "http://127.0.0.1:6333"}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.backend.(*qdrantBackend); !ok {
		t.Fatalf("qdrant: got %T", c.backend)
	}
	if _, err = parseConfig([]string{"-backend", "nope"}, &bytes.Buffer{}); err == nil {
		t.Fatal("unknown backend accepted")
	}
	if _, err = parseConfig([]string{"-backend", "qdrant"}, &bytes.Buffer{}); err == nil {
		t.Fatal("qdrant without url accepted")
	}
}

func TestDefaultsKeepLimits(t *testing.T) {
	c, err := parseConfig([]string{"-store-file", t.TempDir() + "/s.json"}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if c.limits.MaxMetadataBytes != DefaultLimits.MaxMetadataBytes || c.limits.MaxK != DefaultLimits.MaxK {
		t.Fatalf("limits not derived from DefaultLimits: %+v", c.limits)
	}
	if len(c.limits.Collections) != 0 {
		t.Fatal("empty -collections must allow any")
	}
	if e, ok := c.backend.(*embeddedBackend); !ok || e.maxEntries != embeddedMaxEntries {
		t.Fatalf("default max-entries: %+v", c.backend)
	}
}

func TestCollectionsFlagParsing(t *testing.T) {
	c, err := parseConfig([]string{"-collections", "a, b", "-store-file", t.TempDir() + "/s.json"}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.limits.Collections) != 2 || !c.limits.collectionAllowed("a") || !c.limits.collectionAllowed("b") || c.limits.collectionAllowed("c") {
		t.Fatalf("allowlist: %v", c.limits.Collections)
	}
	for _, bad := range []string{"a,,b", "a,b c", "a,"} {
		if _, err := parseConfig([]string{"-collections", bad}, &bytes.Buffer{}); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestCollectionsAllowlist(t *testing.T) {
	be := &fakeBackend{hits: []Hit{}}
	l := testLimits
	l.Collections = map[string]struct{}{"a": {}, "b": {}}
	up := func(col string) string {
		return `{"collection":"` + col + `","text":"x","vector":[1,0],"metadata":{}}`
	}
	se := func(col string) string { return `{"collection":"` + col + `","vector":[1,0],"k":1}` }

	if newServer(be, l) == nil {
		t.Fatal("nil server")
	}
	run := func(tool, args string) (bool, string) {
		t.Helper()
		return callWith(t, be, l, tool, args)
	}
	for _, tc := range []struct{ tool, args string }{
		{"memory_upsert", up("c")},
		{"memory_search", se("c")},
	} {
		isErr, text := run(tc.tool, tc.args)
		if !isErr || text != msgNotAllowed {
			t.Fatalf("%s off-list: isErr=%v text=%q", tc.tool, isErr, text)
		}
		if strings.Contains(text, `"c"`) {
			t.Fatal("collection echoed")
		}
	}
	if len(be.upserted) != 0 {
		t.Fatal("off-list upsert reached the backend")
	}
	for _, tc := range []struct{ tool, args string }{
		{"memory_upsert", up("a")},
		{"memory_search", se("b")},
	} {
		if isErr, text := run(tc.tool, tc.args); isErr {
			t.Fatalf("%s on-list refused: %q", tc.tool, text)
		}
	}
	// Empty allowlist allows any valid name.
	if isErr, text := callWith(t, be, testLimits, "memory_upsert", up("zzz")); isErr {
		t.Fatalf("empty allowlist refused: %q", text)
	}
}

func TestDiagnosticsToStderrNotStdout(t *testing.T) {
	c, err := parseConfig([]string{"-collections", "a", "-credential-env", "SECRET_VAR", "-store-file", t.TempDir() + "/s.json"}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	banner(&out, c)
	if !strings.Contains(out.String(), "memory-store") || strings.Contains(out.String(), "SECRET_VAR") {
		t.Fatalf("banner: %q", out.String())
	}
	// Flag errors go to the writer passed (stderr in main), never stdout.
	var errOut bytes.Buffer
	if _, err := parseConfig([]string{"-bogus"}, &errOut); err == nil || errOut.Len() == 0 {
		t.Fatal("flag error not written to the diagnostic writer")
	}
}
