package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Limits are the handler-enforced bounds on a call's arguments.
type Limits struct {
	MaxK, MaxTextBytes, MaxVectorDim, MaxMetadataBytes int
	// Collections is an optional allowlist. When non-empty, a call naming a
	// collection outside it is refused; when empty, any valid name is allowed.
	Collections map[string]struct{}
}

// collectionAllowed reports whether a call may address the collection.
func (l Limits) collectionAllowed(name string) bool {
	if len(l.Collections) == 0 {
		return true
	}
	_, ok := l.Collections[name]
	return ok
}

// DefaultLimits are the bounds the server runs with.
var DefaultLimits = Limits{MaxK: 64, MaxTextBytes: 16384, MaxVectorDim: 4096, MaxMetadataBytes: 16384}

const maxCallerIDBytes = 256

// The closed set of messages a tool call can fail with. Every error result is
// one of these fixed strings: never an argument's bytes, never a decoder's or
// a backend's error text. The tools are registered through the raw AddTool path,
// so the SDK neither validates nor echoes an argument's value (the schema
// still carries type and required); all validation happens in the handlers
// below.
const (
	msgBadArguments   = "invalid arguments"
	msgBadCollection  = "collection must match [A-Za-z0-9_-]{1,64}"
	msgNotAllowed     = "collection is not served by this store"
	msgBadVector      = "vector must be a non-empty array of finite numbers with a non-zero norm, within the dimension limit"
	msgBadMetadata    = "metadata must be a JSON object"
	msgBadText        = "text must be non-empty and within the size limit"
	msgBadMetaSize    = "metadata exceeds the size limit"
	msgBadID          = "id exceeds the size limit"
	msgBadK           = "k must be between 1 and the maximum"
	msgDimension      = "vector dimension does not match the collection"
	msgCollection     = "collection configuration conflict"
	msgEntryCap       = "the store has reached its entry cap"
	msgStoreCorrupt   = "the store could not be read"
	msgUnavailable    = "the backend is unavailable"
	msgInternalFailed = "the request failed"
)

// fixedErrorStrings enumerates the closed set, for tests that assert an error
// result carries nothing but one of these.
var fixedErrorStrings = []string{
	msgBadArguments, msgBadCollection, msgNotAllowed, msgBadVector, msgBadMetadata, msgBadMetaSize, msgBadText,
	msgBadID, msgBadK, msgDimension, msgCollection, msgEntryCap, msgStoreCorrupt,
	msgUnavailable, msgInternalFailed,
}

var collectionRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

type upsertArgs struct {
	Collection string          `json:"collection"`
	ID         string          `json:"id"`
	Text       string          `json:"text"`
	Vector     []float32       `json:"vector"`
	Metadata   json.RawMessage `json:"metadata"`
}

type searchArgs struct {
	Collection string    `json:"collection"`
	Vector     []float32 `json:"vector"`
	K          int       `json:"k"`
}

type upsertResult struct {
	ID string `json:"id"`
}

type searchResult struct {
	Results []Hit `json:"results"`
}

func fail(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: msg}}}
}

// backendFailure maps a backend error to its fixed message. Anything that is
// not a known sentinel gets the generic message: the error text is dropped.
func backendFailure(err error) *mcp.CallToolResult {
	switch {
	case errors.Is(err, ErrDimensionMismatch):
		return fail(msgDimension)
	case errors.Is(err, ErrCollectionConfig):
		return fail(msgCollection)
	case errors.Is(err, ErrEntryCap):
		return fail(msgEntryCap)
	case errors.Is(err, ErrStoreCorrupt):
		return fail(msgStoreCorrupt)
	case errors.Is(err, ErrBackendUnavailable):
		return fail(msgUnavailable)
	default:
		return fail(msgInternalFailed)
	}
}

// vectorNorm returns the Euclidean norm, accumulated in float64. ok is false
// for a non-finite component or a non-finite norm.
func vectorNorm(v []float32) (norm float64, ok bool) {
	var sum float64
	for _, c := range v {
		f := float64(c)
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return 0, false
		}
		sum += f * f
	}
	norm = math.Sqrt(sum)
	if math.IsNaN(norm) || math.IsInf(norm, 0) {
		return 0, false
	}
	return norm, true
}

func validVector(v []float32, l Limits) bool {
	if len(v) == 0 || len(v) > l.MaxVectorDim {
		return false
	}
	norm, ok := vectorNorm(v)
	return ok && norm > 0
}

func validMetadata(m json.RawMessage) bool {
	m = bytes.TrimSpace(m)
	return len(m) > 0 && m[0] == '{' && json.Valid(m) && utf8.Valid(m)
}

// structured marshals the result inside the handler, so an encoding failure
// becomes a fixed message here instead of the SDK's error text later.
func structured(v any) *mcp.CallToolResult {
	b, err := json.Marshal(v)
	if err != nil {
		return fail(msgInternalFailed)
	}
	return &mcp.CallToolResult{StructuredContent: json.RawMessage(b)}
}

func decodeArgs(req *mcp.CallToolRequest, into any) bool {
	if req == nil || req.Params == nil {
		return false
	}
	return json.Unmarshal(req.Params.Arguments, into) == nil
}

func upsertHandler(be Backend, l Limits) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a upsertArgs
		if !decodeArgs(req, &a) {
			return fail(msgBadArguments), nil
		}
		switch {
		case !collectionRe.MatchString(a.Collection):
			return fail(msgBadCollection), nil
		case !l.collectionAllowed(a.Collection):
			return fail(msgNotAllowed), nil
		case !validVector(a.Vector, l):
			return fail(msgBadVector), nil
		case !validMetadata(a.Metadata):
			return fail(msgBadMetadata), nil
		case len(bytes.TrimSpace(a.Metadata)) > l.MaxMetadataBytes:
			return fail(msgBadMetaSize), nil
		case a.Text == "" || len(a.Text) > l.MaxTextBytes:
			return fail(msgBadText), nil
		case len(a.ID) > maxCallerIDBytes:
			return fail(msgBadID), nil
		}
		id, err := deriveID(a.Collection, a.ID)
		if err != nil {
			return fail(msgInternalFailed), nil
		}
		if err := be.Upsert(ctx, a.Collection, id, a.ID, a.Vector, a.Text, bytes.TrimSpace(a.Metadata)); err != nil {
			return backendFailure(err), nil
		}
		return structured(upsertResult{ID: id}), nil
	}
}

func searchHandler(be Backend, l Limits) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a searchArgs
		if !decodeArgs(req, &a) {
			return fail(msgBadArguments), nil
		}
		switch {
		case !collectionRe.MatchString(a.Collection):
			return fail(msgBadCollection), nil
		case !l.collectionAllowed(a.Collection):
			return fail(msgNotAllowed), nil
		case !validVector(a.Vector, l):
			return fail(msgBadVector), nil
		case a.K < 1 || a.K > l.MaxK:
			return fail(msgBadK), nil
		}
		hits, err := be.Search(ctx, a.Collection, a.Vector, a.K)
		if err != nil {
			return backendFailure(err), nil
		}
		if hits == nil {
			hits = []Hit{}
		}
		return structured(searchResult{Results: hits}), nil
	}
}

// registerTools registers memory_upsert and memory_search through the raw
// AddTool path, so the SDK neither unmarshals nor schema-validates the
// arguments; that, not the schemas, is why the SDK neither validates nor echoes
// a value. The schemas below describe the shape for the model and carry only
// type and required, with no pattern or maxLength as a second line of defense.
func registerTools(server *mcp.Server, be Backend, l Limits) {
	server.AddTool(&mcp.Tool{
		Name:        "memory_upsert",
		Description: "store a text chunk with its embedding vector and JSON metadata in a collection; returns the chunk id",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"collection": map[string]any{"type": "string", "description": "collection name"},
				"id":         map[string]any{"type": "string", "description": "optional stable id; upserting the same id again overwrites"},
				"text":       map[string]any{"type": "string"},
				"vector":     map[string]any{"type": "array", "items": map[string]any{"type": "number"}},
				"metadata":   map[string]any{"type": "object"},
			},
			"required": []string{"collection", "text", "vector", "metadata"},
		},
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false},
	}, upsertHandler(be, l))
	server.AddTool(&mcp.Tool{
		Name:        "memory_search",
		Description: "return the k stored chunks nearest to a query vector in a collection",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"collection": map[string]any{"type": "string", "description": "collection name"},
				"vector":     map[string]any{"type": "array", "items": map[string]any{"type": "number"}},
				"k":          map[string]any{"type": "integer"},
			},
			"required": []string{"collection", "vector", "k"},
		},
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, searchHandler(be, l))
}
