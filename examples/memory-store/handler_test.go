package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var testLimits = Limits{MaxK: 64, MaxTextBytes: 16384, MaxVectorDim: 4096, MaxMetadataBytes: 1024}

const validUpsert = `{"collection":"m","text":"x","vector":[1,0],"metadata":{"a":1}}`

type fakeBackend struct {
	upsertErr error
	searchErr error
	hits      []Hit
	upserted  map[string]string // collection\x00id -> text
	callerIDs []string
}

func (f *fakeBackend) Upsert(_ context.Context, collection, id, callerID string, _ []float32, text string, _ json.RawMessage) error {
	if f.upsertErr != nil {
		return f.upsertErr
	}
	if f.upserted == nil {
		f.upserted = map[string]string{}
	}
	f.upserted[collection+"\x00"+id] = text
	f.callerIDs = append(f.callerIDs, callerID)
	return nil
}

func (f *fakeBackend) Search(_ context.Context, _ string, _ []float32, k int) ([]Hit, error) {
	if f.searchErr != nil {
		return nil, f.searchErr
	}
	if len(f.hits) > k {
		return f.hits[:k], nil
	}
	return f.hits, nil
}

// handlerFor returns the registered handler by tool name.
func handlerFor(t *testing.T, be Backend, name string) mcp.ToolHandler {
	t.Helper()
	switch name {
	case "memory_upsert":
		return upsertHandler(be, testLimits)
	case "memory_search":
		return searchHandler(be, testLimits)
	}
	t.Fatalf("unknown tool %q", name)
	return nil
}

func callRawWith(t *testing.T, be Backend, name, raw string) *mcp.CallToolResult {
	t.Helper()
	req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: name, Arguments: json.RawMessage(raw)}}
	res, err := handlerFor(t, be, name)(context.Background(), req)
	if err != nil {
		t.Fatalf("handler must never return a Go error to the SDK, got: %v", err)
	}
	if res == nil {
		t.Fatal("nil result")
	}
	return res
}

func callRaw(t *testing.T, name, raw string) *mcp.CallToolResult {
	t.Helper()
	return callRawWith(t, &fakeBackend{}, name, raw)
}

func resultBytes(t *testing.T, res *mcp.CallToolResult) []byte {
	t.Helper()
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func assertFixedString(t *testing.T, res *mcp.CallToolResult) {
	t.Helper()
	if !res.IsError {
		t.Fatal("expected an error result")
	}
	if len(res.Content) != 1 {
		t.Fatalf("expected exactly one content item, got %d", len(res.Content))
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("error content is %T, want *mcp.TextContent", res.Content[0])
	}
	for _, s := range fixedErrorStrings {
		if tc.Text == s {
			return
		}
	}
	t.Fatalf("error message %q is not in the closed set", tc.Text)
}

func structuredJSON(t *testing.T, res *mcp.CallToolResult) []byte {
	t.Helper()
	if res.IsError {
		t.Fatalf("unexpected error result: %s", resultBytes(t, res))
	}
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func idx(b []byte, s string) int { return bytes.Index(b, []byte(s)) }

func TestUpsertWrongTypedArgLeaksNothing(t *testing.T) {
	raw := `{"collection":"meetings","text":"SECRET-SENTINEL-7Q","vector":"not-an-array","metadata":{}}`
	res := callRaw(t, "memory_upsert", raw)
	if !res.IsError {
		t.Fatal("a non-array vector must be a handler error")
	}
	rb := resultBytes(t, res)
	if bytes.Contains(rb, []byte("SECRET-SENTINEL-7Q")) || bytes.Contains(rb, []byte("not-an-array")) {
		t.Fatalf("the result leaked an argument value: %s", rb)
	}
	assertFixedString(t, res)
}

func TestMalformedJSONLeaksNothing(t *testing.T) {
	res := callRaw(t, "memory_upsert", `{"collection":"SECRET-SENTINEL-7Q", `)
	rb := resultBytes(t, res)
	if bytes.Contains(rb, []byte("SECRET-SENTINEL-7Q")) || bytes.Contains(rb, []byte("unexpected")) {
		t.Fatalf("leaked decoder detail: %s", rb)
	}
	assertFixedString(t, res)
}

func TestUpsertOverLongTextLeaksNothing(t *testing.T) {
	text := strings.Repeat("Z", 1<<20)
	raw := fmt.Sprintf(`{"collection":"m","text":%q,"vector":[1,0],"metadata":{}}`, text)
	res := callRaw(t, "memory_upsert", raw)
	if !res.IsError {
		t.Fatal("over-long text must be refused")
	}
	if bytes.Contains(resultBytes(t, res), []byte("ZZZZ")) {
		t.Fatal("the result leaked argument text")
	}
	assertFixedString(t, res)
}

// TestSearchResultFieldOrder asserts the server-side wire shape of the result
// (field order as this server serializes it). It does not assert what a
// gateway previews after re-marshalling the result.
func TestSearchResultFieldOrder(t *testing.T) {
	be := &fakeBackend{hits: []Hit{{ID: "11111111-1111-4111-8111-111111111111", Score: 0.5, Text: "retrieved", Metadata: json.RawMessage(`{"a":1}`)}}}
	res := callRawWith(t, be, "memory_search", `{"collection":"m","vector":[1,0],"k":1}`)
	if res.Content != nil {
		t.Fatal("Content must be nil; structured content carries the results")
	}
	j := structuredJSON(t, res)
	iID, iScore, iText, iMeta := idx(j, `"id"`), idx(j, `"score"`), idx(j, `"text"`), idx(j, `"metadata"`)
	if iID < 0 || iScore < 0 || iText < 0 || iMeta < 0 {
		t.Fatalf("missing field in %s", j)
	}
	if iID >= iScore || iScore >= iText || iText >= iMeta {
		t.Fatalf("fields must be ordered id, score, text, metadata: %s", j)
	}
	if !strings.HasPrefix(string(j), `{"results":[{"id"`) {
		t.Fatalf("unexpected result shape: %s", j)
	}
}

func TestSearchEmptyResultsIsArray(t *testing.T) {
	res := callRaw(t, "memory_search", `{"collection":"m","vector":[1,0],"k":3}`)
	if got := string(structuredJSON(t, res)); got != `{"results":[]}` {
		t.Fatalf("empty search must be an empty array, got %s", got)
	}
}

func TestCollectionCharsetRejected(t *testing.T) {
	for _, bad := range []string{"", "a/b", "a.b", "../x", strings.Repeat("a", 65), "a b", "a%2e"} {
		for _, tool := range []struct{ name, tmpl string }{
			{"memory_search", `{"collection":%q,"vector":[1,0],"k":1}`},
			{"memory_upsert", `{"collection":%q,"text":"x","vector":[1,0],"metadata":{}}`},
		} {
			res := callRaw(t, tool.name, fmt.Sprintf(tool.tmpl, bad))
			if !res.IsError {
				t.Fatalf("%s: collection %q must be refused", tool.name, bad)
			}
			assertFixedString(t, res)
		}
	}
	for _, good := range []string{"a", "A_b-9", strings.Repeat("a", 64)} {
		res := callRaw(t, "memory_search", fmt.Sprintf(`{"collection":%q,"vector":[1,0],"k":1}`, good))
		if res.IsError {
			t.Fatalf("collection %q must be accepted", good)
		}
	}
}

func TestVectorRejected(t *testing.T) {
	for _, v := range []string{`[]`, `[NaN]`, `[0,0]`, `null`, `[1e999]`, `["a"]`} {
		res := callRaw(t, "memory_search", `{"collection":"m","vector":`+v+`,"k":1}`)
		if !res.IsError {
			t.Fatalf("vector %s must be refused", v)
		}
		assertFixedString(t, res)
	}
	// Missing vector entirely.
	res := callRaw(t, "memory_search", `{"collection":"m","k":1}`)
	if !res.IsError {
		t.Fatal("missing vector must be refused")
	}
	assertFixedString(t, res)
}

func TestVectorNormUsesFloat64(t *testing.T) {
	// float32 squares would overflow (1e30^2 = 1e60 > MaxFloat32) but the
	// float64 norm is finite and non-zero, so this vector is valid.
	res := callRaw(t, "memory_search", `{"collection":"m","vector":[1e30,1e30],"k":1}`)
	if res.IsError {
		t.Fatalf("large finite vector must be accepted: %s", resultBytes(t, res))
	}
	// A vector of tiny magnitudes underflows in float32 but not float64.
	res = callRaw(t, "memory_search", `{"collection":"m","vector":[1e-30,1e-30],"k":1}`)
	if res.IsError {
		t.Fatalf("tiny non-zero vector must be accepted: %s", resultBytes(t, res))
	}
}

func TestMetadataRequiredObject(t *testing.T) {
	for _, m := range []string{``, `"metadata":5,`, `"metadata":[],`, `"metadata":null,`, `"metadata":"s",`} {
		res := callRaw(t, "memory_upsert", `{"collection":"m","text":"x","vector":[1,0],`+m+`"id":"i"}`)
		if !res.IsError {
			t.Fatalf("metadata %q must be refused", m)
		}
		assertFixedString(t, res)
	}
}

func TestMetadataInvalidUTF8Refused(t *testing.T) {
	res := callRaw(t, "memory_upsert", "{\"collection\":\"m\",\"text\":\"x\",\"vector\":[1,0],\"metadata\":{\"k\":\"a\xffb\"},\"id\":\"i\"}")
	if !res.IsError {
		t.Fatal("invalid UTF-8 metadata must be refused")
	}
	assertFixedString(t, res)
	if bytes.Contains(resultBytes(t, res), []byte{0xff}) {
		t.Fatal("argument bytes leaked")
	}
}

func TestBoundsEnforced(t *testing.T) {
	big := make([]string, testLimits.MaxVectorDim+1)
	for i := range big {
		big[i] = "1"
	}
	longVec := "[" + strings.Join(big, ",") + "]"
	cases := []struct{ name, tool, raw string }{
		{"k=0", "memory_search", `{"collection":"m","vector":[1,0],"k":0}`},
		{"k missing", "memory_search", `{"collection":"m","vector":[1,0]}`},
		{"k negative", "memory_search", `{"collection":"m","vector":[1,0],"k":-1}`},
		{"k>max", "memory_search", fmt.Sprintf(`{"collection":"m","vector":[1,0],"k":%d}`, testLimits.MaxK+1)},
		{"text>max", "memory_upsert", fmt.Sprintf(`{"collection":"m","text":%q,"vector":[1,0],"metadata":{}}`, strings.Repeat("a", testLimits.MaxTextBytes+1))},
		{"vector>max", "memory_upsert", `{"collection":"m","text":"x","vector":` + longVec + `,"metadata":{}}`},
		{"search vector>max", "memory_search", `{"collection":"m","vector":` + longVec + `,"k":1}`},
	}
	for _, c := range cases {
		res := callRaw(t, c.tool, c.raw)
		if !res.IsError {
			t.Fatalf("%s must be refused", c.name)
		}
		assertFixedString(t, res)
	}
	// Boundaries are inclusive.
	ok := callRaw(t, "memory_search", fmt.Sprintf(`{"collection":"m","vector":[1,0],"k":%d}`, testLimits.MaxK))
	if ok.IsError {
		t.Fatal("k == MaxK must be accepted")
	}
	ok = callRaw(t, "memory_upsert", fmt.Sprintf(`{"collection":"m","text":%q,"vector":[1,0],"metadata":{}}`, strings.Repeat("a", testLimits.MaxTextBytes)))
	if ok.IsError {
		t.Fatal("text == MaxTextBytes must be accepted")
	}
}

func TestUpsertReturnsDerivedID(t *testing.T) {
	be := &fakeBackend{}
	res := callRawWith(t, be, "memory_upsert", `{"collection":"m","text":"x","vector":[1,0],"metadata":{"a":1},"id":"chunk-1"}`)
	want, _ := deriveID("m", "chunk-1")
	if got := string(structuredJSON(t, res)); got != `{"id":"`+want+`"}` {
		t.Fatalf("got %s, want id %s", got, want)
	}
	if be.upserted["m\x00"+want] != "x" {
		t.Fatalf("backend was not called with the derived id: %v", be.upserted)
	}
}

func TestUpsertRandomIDWhenAbsent(t *testing.T) {
	a := structuredJSON(t, callRaw(t, "memory_upsert", validUpsert))
	b := structuredJSON(t, callRaw(t, "memory_upsert", validUpsert))
	if bytes.Equal(a, b) {
		t.Fatalf("absent id must yield a fresh random id each time: %s", a)
	}
}

// newSession connects an in-memory client to a server whose tools are
// registered through registerTools, i.e. the real SDK path.
func newSession(t *testing.T, be Backend) *mcp.ClientSession {
	t.Helper()
	server := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "v0"}, nil)
	registerTools(server, be, testLimits)
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "v0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// sessionCall calls a tool through the SDK session with raw JSON arguments.
func sessionCall(t *testing.T, be Backend, name, raw string) *mcp.CallToolResult {
	t.Helper()
	res, err := newSession(t, be).CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: json.RawMessage(raw)})
	if err != nil {
		t.Fatalf("the raw path must return the failure in the result, not as a protocol error: %v", err)
	}
	return res
}

func TestSessionWrongTypedArgLeaksNothing(t *testing.T) {
	raw := `{"collection":"meetings","text":"SECRET-SENTINEL-7Q","vector":"not-an-array","metadata":{}}`
	res := sessionCall(t, &fakeBackend{}, "memory_upsert", raw)
	rb := resultBytes(t, res)
	if bytes.Contains(rb, []byte("SECRET-SENTINEL-7Q")) || bytes.Contains(rb, []byte("not-an-array")) {
		t.Fatalf("the result leaked an argument value: %s", rb)
	}
	assertFixedString(t, res)
}

func TestSessionOverLongTextLeaksNothing(t *testing.T) {
	raw := fmt.Sprintf(`{"collection":"m","text":%q,"vector":[1,0],"metadata":{}}`, strings.Repeat("Z", 1<<20))
	res := sessionCall(t, &fakeBackend{}, "memory_upsert", raw)
	if bytes.Contains(resultBytes(t, res), []byte("ZZZZ")) {
		t.Fatal("the result leaked argument text")
	}
	assertFixedString(t, res)
}

func TestSessionBackendErrorLeaksNothing(t *testing.T) {
	be := &fakeBackend{upsertErr: fmt.Errorf("%w: %w", ErrEntryCap, &os.PathError{Op: "open", Path: "/secret/path", Err: os.ErrPermission})}
	res := sessionCall(t, be, "memory_upsert", validUpsert)
	if bytes.Contains(resultBytes(t, res), []byte("/secret/path")) {
		t.Fatal("backend error text leaked")
	}
	assertFixedString(t, res)
}

func TestNonFiniteScoreIsFixedString(t *testing.T) {
	be := &fakeBackend{hits: []Hit{{ID: "i", Score: float32(math.Inf(1)), Text: "t", Metadata: json.RawMessage(`{}`)}}}
	for name, res := range map[string]*mcp.CallToolResult{
		"handler": callRawWith(t, be, "memory_search", `{"collection":"m","vector":[1,0],"k":1}`),
		"session": sessionCall(t, be, "memory_search", `{"collection":"m","vector":[1,0],"k":1}`),
	} {
		assertFixedString(t, res)
		rb := bytes.ToLower(resultBytes(t, res))
		if bytes.Contains(rb, []byte("json")) || bytes.Contains(rb, []byte("encoding")) || bytes.Contains(rb, []byte("unsupported")) {
			t.Fatalf("%s: encoder text leaked: %s", name, rb)
		}
	}
}

func TestSearchReadOnlyHint(t *testing.T) {
	cs := newSession(t, &fakeBackend{})
	ctx := context.Background()
	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	hint := map[string]bool{}
	for _, tl := range tools.Tools {
		if tl.Annotations == nil {
			t.Fatalf("tool %s has no annotations", tl.Name)
		}
		hint[tl.Name] = tl.Annotations.ReadOnlyHint
		// The schema must carry no constraint the SDK could enforce and echo.
		sb, _ := json.Marshal(tl.InputSchema)
		for _, kw := range []string{`"pattern"`, `"maxLength"`, `"maximum"`} {
			if bytes.Contains(sb, []byte(kw)) {
				t.Fatalf("tool %s schema carries %s", tl.Name, kw)
			}
		}
	}
	if len(hint) != 2 {
		t.Fatalf("expected 2 tools, got %v", hint)
	}
	if !hint["memory_search"] || hint["memory_upsert"] {
		t.Fatalf("ReadOnlyHint wrong: %v", hint)
	}

	// End to end through the SDK: an over-bound k is refused by the handler,
	// not by schema validation, with a fixed message.
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "memory_search", Arguments: map[string]any{"collection": "m", "vector": []float32{1, 0}, "k": 9999}})
	if err != nil {
		t.Fatalf("over-bound k must be a tool error result, not a protocol error: %v", err)
	}
	assertFixedString(t, res)
}

func TestBackendSentinelMapsToFixedString(t *testing.T) {
	sentinels := []error{ErrDimensionMismatch, ErrCollectionConfig, ErrEntryCap, ErrStoreCorrupt, ErrBackendUnavailable}
	for _, s := range sentinels {
		leaky := fmt.Errorf("%w: %w", s, &os.PathError{Op: "open", Path: "/secret/path", Err: os.ErrPermission})
		be := &fakeBackend{upsertErr: leaky, searchErr: leaky}
		for _, c := range []struct{ tool, raw string }{
			{"memory_upsert", validUpsert},
			{"memory_search", `{"collection":"m","vector":[1,0],"k":1}`},
		} {
			res := callRawWith(t, be, c.tool, c.raw)
			if bytes.Contains(resultBytes(t, res), []byte("/secret/path")) {
				t.Fatalf("%v: backend error text leaked", s)
			}
			assertFixedString(t, res)
		}
	}
}

func TestUnknownBackendErrorMapsToFixedString(t *testing.T) {
	be := &fakeBackend{upsertErr: fmt.Errorf("dial tcp 10.0.0.9:6334: SECRET-HOST")}
	res := callRawWith(t, be, "memory_upsert", validUpsert)
	if bytes.Contains(resultBytes(t, res), []byte("SECRET-HOST")) {
		t.Fatal("unclassified backend error leaked")
	}
	assertFixedString(t, res)
}

func TestSentinelsMapToDistinctMessages(t *testing.T) {
	seen := map[string]error{}
	for _, s := range []error{ErrDimensionMismatch, ErrCollectionConfig, ErrEntryCap, ErrStoreCorrupt, ErrBackendUnavailable} {
		res := callRawWith(t, &fakeBackend{upsertErr: s}, "memory_upsert", validUpsert)
		assertFixedString(t, res)
		msg := res.Content[0].(*mcp.TextContent).Text
		if prev, dup := seen[msg]; dup {
			t.Fatalf("%v and %v share message %q", prev, s, msg)
		}
		seen[msg] = s
	}
}

func TestNonFiniteVectorComponentRejected(t *testing.T) {
	// 1e400 overflows float32 (and float64); it must not become +Inf.
	for _, v := range []string{`[1e400,1]`, `[-1e400,1]`, `[1e39,1]`} {
		for _, tool := range []struct{ name, tmpl string }{
			{"memory_search", `{"collection":"m","vector":%s,"k":1}`},
			{"memory_upsert", `{"collection":"m","text":"x","vector":%s,"metadata":{}}`},
		} {
			res := callRaw(t, tool.name, fmt.Sprintf(tool.tmpl, v))
			if !res.IsError {
				t.Fatalf("%s: vector %s must be refused", tool.name, v)
			}
			assertFixedString(t, res)
		}
	}
}

func TestEmptyTextRejected(t *testing.T) {
	for _, body := range []string{
		`{"collection":"m","text":"","vector":[1,0],"metadata":{}}`,
		`{"collection":"m","vector":[1,0],"metadata":{}}`,
	} {
		res := callRaw(t, "memory_upsert", body)
		if !res.IsError {
			t.Fatalf("%s must be refused", body)
		}
		assertFixedString(t, res)
	}
}

func TestMetadataSizeCapHasOwnMessage(t *testing.T) {
	big := `{"k":"` + strings.Repeat("a", testLimits.MaxMetadataBytes) + `"}`
	res := callRaw(t, "memory_upsert", `{"collection":"m","text":"x","vector":[1,0],"metadata":`+big+`}`)
	assertFixedString(t, res)
	if got := res.Content[0].(*mcp.TextContent).Text; got != msgBadMetaSize {
		t.Fatalf("got %q, want the metadata size message", got)
	}
	if msgBadMetaSize == msgBadMetadata {
		t.Fatal("size and shape messages must differ")
	}
	// Exactly at the cap is accepted.
	pad := testLimits.MaxMetadataBytes - len(`{"k":""}`)
	okMeta := `{"k":"` + strings.Repeat("a", pad) + `"}`
	if len(okMeta) != testLimits.MaxMetadataBytes {
		t.Fatalf("test bug: len %d", len(okMeta))
	}
	if res := callRaw(t, "memory_upsert", `{"collection":"m","text":"x","vector":[1,0],"metadata":`+okMeta+`}`); res.IsError {
		t.Fatal("metadata at the cap must be accepted")
	}
}

func TestCallerIDCap(t *testing.T) {
	long := strings.Repeat("a", maxCallerIDBytes+1)
	res := callRaw(t, "memory_upsert", `{"collection":"m","text":"x","vector":[1,0],"metadata":{},"id":"`+long+`"}`)
	assertFixedString(t, res)
	if got := res.Content[0].(*mcp.TextContent).Text; got != msgBadID {
		t.Fatalf("got %q, want the id size message", got)
	}
	ok := strings.Repeat("a", maxCallerIDBytes)
	if res := callRaw(t, "memory_upsert", `{"collection":"m","text":"x","vector":[1,0],"metadata":{},"id":"`+ok+`"}`); res.IsError {
		t.Fatal("id at the cap must be accepted")
	}
}

func TestBackendReceivesCallerID(t *testing.T) {
	be := &fakeBackend{}
	callRawWith(t, be, "memory_upsert", `{"collection":"m","text":"x","vector":[1,0],"metadata":{},"id":"chunk-9"}`)
	callRawWith(t, be, "memory_upsert", validUpsert)
	if len(be.callerIDs) != 2 || be.callerIDs[0] != "chunk-9" || be.callerIDs[1] != "" {
		t.Fatalf("callerIDs = %q, want [chunk-9 \"\"]", be.callerIDs)
	}
}

func TestVectorNormHelper(t *testing.T) {
	if _, ok := vectorNorm([]float32{float32(math.Inf(1))}); ok {
		t.Fatal("infinite component must be rejected")
	}
	if _, ok := vectorNorm([]float32{float32(math.NaN())}); ok {
		t.Fatal("NaN component must be rejected")
	}
}
