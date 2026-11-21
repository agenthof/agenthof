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
	// A whitespace-only value must fail closed, never mean allow-any.
	for _, bad := range []string{"a,,b", "a,b c", "a,", " ", "\t", ", "} {
		if _, err := parseConfig([]string{"-collections", bad, "-store-file", "s.json"}, &bytes.Buffer{}); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	c, err = parseConfig([]string{"-collections", "", "-store-file", "s.json"}, &bytes.Buffer{})
	if err != nil || len(c.limits.Collections) != 0 {
		t.Fatalf("empty -collections must allow any: %v", err)
	}
}

func TestStrayPositionalArgumentsRejected(t *testing.T) {
	// flag stops at the first non-flag token; without the check this would
	// start with an empty allowlist and an in-process default backend.
	var errOut bytes.Buffer
	_, err := parseConfig([]string{"stray", "-collections", "a", "-store-file", "s.json"}, &errOut)
	if err == nil {
		t.Fatal("stray positional argument accepted")
	}
	if strings.Contains(err.Error(), "stray") || strings.Contains(err.Error(), "-collections") {
		t.Fatalf("error echoes the argument: %q", err)
	}
	if _, err := parseConfig([]string{"-store-file", "s.json", "--", "x"}, &errOut); err == nil {
		t.Fatal("trailing positional argument accepted")
	}
}

func TestEmptyStoreFileRejected(t *testing.T) {
	for _, v := range []string{"", "  ", "\t"} {
		_, err := parseConfig([]string{"-backend", "embedded", "-store-file", v}, &bytes.Buffer{})
		if err == nil {
			t.Fatalf("blank -store-file %q accepted for embedded", v)
		}
		if want := "-store-file must not be empty for the embedded backend"; err.Error() != want {
			t.Fatalf("blank -store-file %q: error %q, want %q", v, err, want)
		}
	}
	if _, err := parseConfig([]string{"-backend", "qdrant", "-qdrant-url", "http://127.0.0.1:6333", "-store-file", ""}, &bytes.Buffer{}); err != nil {
		t.Fatalf("qdrant must ignore -store-file: %v", err)
	}
}

func TestCredentialEnvNeverReachesQdrantAuth(t *testing.T) {
	c, err := parseConfig([]string{"-backend", "qdrant", "-qdrant-url", "http://127.0.0.1:6333", "-credential-env", "PLACEHOLDER_BEARER"}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	q, ok := c.backend.(*qdrantBackend)
	if !ok {
		t.Fatalf("got %T", c.backend)
	}
	if q.authEnv != "" {
		t.Fatalf("qdrant auth env = %q, want empty", q.authEnv)
	}
	c, err = parseConfig([]string{"-backend", "qdrant", "-qdrant-url", "http://127.0.0.1:6333", "-credential-env", "X", "-qdrant-auth", "QKEY"}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if got := c.backend.(*qdrantBackend).authEnv; got != "QKEY" {
		t.Fatalf("qdrant auth env = %q, want QKEY", got)
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
		{"memory_upsert", up("offlistname")},
		{"memory_search", se("offlistname")},
	} {
		isErr, text := run(tc.tool, tc.args)
		if !isErr || text != msgNotAllowed {
			t.Fatalf("%s off-list: isErr=%v text=%q", tc.tool, isErr, text)
		}
		if strings.Contains(text, "offlistname") {
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
