package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func connect(t *testing.T) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	clientT, serverT := mcp.NewInMemoryTransports()
	ss, err := newServer().Connect(ctx, serverT, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "v0"}, nil).Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (string, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool %s: %v", name, err)
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("CallTool %s: content %T is not text", name, res.Content[0])
	}
	return text.Text, res.IsError
}

func TestListToolsNamesAndArgs(t *testing.T) {
	cs := connect(t)
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	want := map[string][]string{
		"search":        {"query"},
		"readGoogleDoc": {"documentId"},
		"downloadFile":  {"fileId", "localPath"},
	}
	if len(res.Tools) != len(want) {
		t.Fatalf("got %d tools, want %d", len(res.Tools), len(want))
	}
	for _, tool := range res.Tools {
		props, ok := want[tool.Name]
		if !ok {
			t.Fatalf("unexpected tool %q", tool.Name)
		}
		schema, ok := tool.InputSchema.(map[string]any)
		if !ok {
			t.Fatalf("tool %s: input schema %T is not an object", tool.Name, tool.InputSchema)
		}
		properties, _ := schema["properties"].(map[string]any)
		got := []string{}
		for name := range properties {
			got = append(got, name)
		}
		sort.Strings(got)
		sort.Strings(props)
		if strings.Join(got, ",") != strings.Join(props, ",") {
			t.Fatalf("tool %s: properties %v, want %v", tool.Name, got, props)
		}
	}
}

func TestSearchCanned(t *testing.T) {
	cs := connect(t)
	got, isErr := call(t, cs, "search", map[string]any{"query": "roadmap"})
	if isErr || got != "note-1 Roadmap notes" {
		t.Fatalf("search roadmap = %q (error %v)", got, isErr)
	}
	again, _ := call(t, cs, "search", map[string]any{"query": "roadmap"})
	if again != got {
		t.Fatalf("search not deterministic: %q vs %q", got, again)
	}
	both, _ := call(t, cs, "search", map[string]any{"query": "notes"})
	if !strings.Contains(both, "note-1 ") || !strings.Contains(both, "note-2 ") {
		t.Fatalf("search notes = %q, want both notes", both)
	}
}

func TestReadGoogleDocCanned(t *testing.T) {
	cs := connect(t)
	got, isErr := call(t, cs, "readGoogleDoc", map[string]any{"documentId": "note-1"})
	if isErr || !strings.Contains(got, "Roadmap") {
		t.Fatalf("readGoogleDoc note-1 = %q (error %v)", got, isErr)
	}
	msg, isErr := call(t, cs, "readGoogleDoc", map[string]any{"documentId": "nope"})
	if !isErr || msg != "document not found: nope" {
		t.Fatalf("unknown id = %q (error %v)", msg, isErr)
	}
}

func TestDatedNotes(t *testing.T) {
	cs := connect(t)
	hits, isErr := call(t, cs, "search", map[string]any{"query": "sync"})
	if isErr {
		t.Fatalf("search sync errored: %q", hits)
	}
	for _, id := range []string{"note-3 ", "note-4 ", "note-5 "} {
		if !strings.Contains(hits, id) {
			t.Fatalf("search sync = %q, want %q", hits, id)
		}
	}
	if strings.Contains(hits, "note-1 ") || strings.Contains(hits, "note-2 ") {
		t.Fatalf("search sync = %q, must not match the undated notes", hits)
	}
	for id, date := range map[string]string{"note-3": "2026-09-14", "note-4": "2026-09-21", "note-5": "2026-09-28"} {
		body, isErr := call(t, cs, "readGoogleDoc", map[string]any{"documentId": id})
		if isErr || !strings.HasPrefix(body, "Meeting notes - "+date+"\n") {
			t.Fatalf("readGoogleDoc %s = %q (error %v), want a dated header %s", id, body, isErr, date)
		}
		if want := map[string]string{"note-3": "entitlement", "note-4": "JWT"}[id]; want != "" && !strings.Contains(body, want) {
			t.Fatalf("readGoogleDoc %s lacks its topic %q", id, want)
		}
		if strings.Count(body, "\n\n") < 3 {
			t.Fatalf("readGoogleDoc %s has too few paragraphs to chunk", id)
		}
	}
}

func TestReadGoogleDocErrorCanary(t *testing.T) {
	cs := connect(t)
	got, isErr := call(t, cs, "readGoogleDoc", map[string]any{"documentId": "__error__:CANARY123"})
	if !isErr || !strings.HasPrefix(got, "CANARY123") {
		t.Fatalf("error canary = %q (error %v)", got, isErr)
	}
	if n := utf8.RuneCountInString(got); n <= 200 {
		t.Fatalf("error text is %d runes, want more than 200", n)
	}
}

func TestCredentialFingerprintLine(t *testing.T) {
	sum := sha256.Sum256([]byte("secret"))
	fp := hex.EncodeToString(sum[:])
	set := credentialFingerprintLine(func(n string) (string, bool) {
		return "secret", n == "GOOGLE_DRIVE_MCP_REFRESH_TOKEN"
	})
	if want := "fake-drive-mcp: credential GOOGLE_DRIVE_MCP_REFRESH_TOKEN fingerprint " + fp; set != want {
		t.Fatalf("set line = %q, want %q", set, want)
	}
	const wantUnset = "fake-drive-mcp: credential GOOGLE_DRIVE_MCP_REFRESH_TOKEN not set"
	unset := credentialFingerprintLine(func(string) (string, bool) { return "", false })
	if unset != wantUnset {
		t.Fatalf("unset line = %q, want %q", unset, wantUnset)
	}
	empty := credentialFingerprintLine(func(string) (string, bool) { return "", true })
	if empty != wantUnset {
		t.Fatalf("set-but-empty line = %q, want %q", empty, wantUnset)
	}
}
