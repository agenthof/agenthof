package main

import (
	"context"
	"encoding/json"
	"errors"
)

// Hit is one search result. The field order is the server's wire shape; the
// gateway re-serializes the decoded result with keys sorted alphabetically,
// so the gateway's ledger preview shows a different order.
type Hit struct {
	ID       string          `json:"id"`
	Score    float32         `json:"score"`
	Text     string          `json:"text"`
	Metadata json.RawMessage `json:"metadata"`
}

// Backend is a vector store. Implementations return only the sentinel errors
// below (possibly wrapped); the handler maps them to fixed messages and never
// forwards a backend error's text to the caller.
type Backend interface {
	// id is the derived UUID; callerID is the caller's original id, or "" when
	// none was sent. Backends persist callerID as its own field, never inside
	// the caller's metadata.
	Upsert(ctx context.Context, collection, id, callerID string, vec []float32, text string, meta json.RawMessage) error
	Search(ctx context.Context, collection string, vec []float32, k int) ([]Hit, error)
}

var (
	// ErrDimensionMismatch: the vector's length differs from the collection's.
	ErrDimensionMismatch = errors.New("vector dimension does not match the collection")
	// ErrCollectionConfig: the collection exists with an incompatible configuration.
	ErrCollectionConfig = errors.New("collection configuration conflict")
	// ErrEntryCap: the embedded store's hard entry cap is reached.
	ErrEntryCap = errors.New("entry cap reached")
	// ErrStoreCorrupt: the persisted store could not be read back.
	ErrStoreCorrupt = errors.New("store is corrupt")
	// ErrBackendUnavailable: the backend could not be reached.
	ErrBackendUnavailable = errors.New("backend unavailable")
)
