package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// qdrantMaxBody bounds every response read from the Qdrant service.
const qdrantMaxBody = 16 << 20

// qdrantBackend talks to a Qdrant service over its REST API using only the
// standard library. Target image: current-stable qdrant/qdrant; the concrete
// @sha256 and resolved version are pinned by the memory acceptance script added
// in a later task (the Query API needs Qdrant >= 1.10).
//
// The client never uses a proxy and never follows a redirect, so a configured
// base URL cannot be bounced to another host. No response body is ever
// returned as an error: every failure is one of the Backend sentinels.
type qdrantBackend struct {
	base    string // scheme://host[:port][/prefix], no trailing slash
	authEnv string // name of the env var holding the api key, "" for none
	client  *http.Client

	mu       sync.Mutex // guards probed and verified
	probed   bool
	verified map[string]int // collection -> verified vector size
}

func newQdrantBackend(baseURL, authEnv string) (*qdrantBackend, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, errors.New("qdrant url: not a valid url")
	}
	switch {
	case u.Scheme != "http" && u.Scheme != "https":
		return nil, errors.New("qdrant url: scheme must be http or https")
	case u.Hostname() == "":
		return nil, errors.New("qdrant url: host is required")
	case u.User != nil:
		return nil, errors.New("qdrant url: userinfo is not allowed")
	case u.RawQuery != "" || u.ForceQuery:
		return nil, errors.New("qdrant url: query is not allowed")
	case u.Fragment != "" || strings.Contains(baseURL, "#"):
		return nil, errors.New("qdrant url: fragment is not allowed")
	}
	tr, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("qdrant: unexpected default transport")
	}
	tr = tr.Clone()
	tr.Proxy = nil
	return &qdrantBackend{
		base:    strings.TrimRight(u.String(), "/"),
		authEnv: authEnv,
		client: &http.Client{
			Transport: tr,
			Timeout:   30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		verified: map[string]int{},
	}, nil
}

// do performs one request. Any transport error, redirect, or oversized body
// is ErrBackendUnavailable; the caller interprets the status.
func (b *qdrantBackend) do(ctx context.Context, method, path string, body any) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(body); err != nil {
			return 0, nil, ErrBackendUnavailable
		}
		rd = &buf
	}
	req, err := http.NewRequestWithContext(ctx, method, b.base+path, rd)
	if err != nil {
		return 0, nil, ErrBackendUnavailable
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if b.authEnv != "" {
		if key := os.Getenv(b.authEnv); key != "" {
			req.Header.Set("api-key", key)
		}
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return 0, nil, ErrBackendUnavailable
	}
	data, rerr := io.ReadAll(io.LimitReader(resp.Body, qdrantMaxBody+1))
	if cerr := resp.Body.Close(); cerr != nil && rerr == nil {
		rerr = cerr
	}
	if rerr != nil || len(data) > qdrantMaxBody {
		return 0, nil, ErrBackendUnavailable
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return 0, nil, ErrBackendUnavailable
	}
	return resp.StatusCode, data, nil
}

// probe checks once that the base URL really is a Qdrant service root.
// Callers hold b.mu.
func (b *qdrantBackend) probe(ctx context.Context) error {
	if b.probed {
		return nil
	}
	status, data, err := b.do(ctx, http.MethodGet, "/", nil)
	if err != nil {
		return err
	}
	var root struct {
		Title string `json:"title"`
	}
	if status != http.StatusOK || json.Unmarshal(data, &root) != nil ||
		!strings.HasPrefix(strings.ToLower(root.Title), "qdrant") {
		return ErrBackendUnavailable
	}
	b.probed = true
	return nil
}

func collectionPath(collection string) string {
	return "/collections/" + url.PathEscape(collection)
}

// ensureCollection creates the collection as Cosine (an existing one is
// fine), then reads it back and verifies it before the first write.
// Callers hold b.mu.
func (b *qdrantBackend) ensureCollection(ctx context.Context, collection string, dim int) error {
	if size, ok := b.verified[collection]; ok {
		if size != dim {
			return ErrDimensionMismatch
		}
		return nil
	}
	status, data, err := b.do(ctx, http.MethodPut, collectionPath(collection),
		map[string]any{"vectors": map[string]any{"size": dim, "distance": "Cosine"}})
	if err != nil {
		return err
	}
	exists := status == http.StatusConflict ||
		(status == http.StatusBadRequest && bytes.Contains(bytes.ToLower(data), []byte("already exists")))
	if status != http.StatusOK && !exists {
		return ErrBackendUnavailable
	}
	size, found, err := b.readCollection(ctx, collection)
	if err != nil {
		return err
	}
	if !found {
		return ErrBackendUnavailable
	}
	if size != dim {
		return ErrDimensionMismatch
	}
	return nil
}

// readCollection reads the collection back, verifies it, and caches its
// vector size. found is false when the collection does not exist.
// Callers hold b.mu.
func (b *qdrantBackend) readCollection(ctx context.Context, collection string) (size int, found bool, err error) {
	status, data, err := b.do(ctx, http.MethodGet, collectionPath(collection), nil)
	if err != nil {
		return 0, false, err
	}
	if status == http.StatusNotFound {
		return 0, false, nil
	}
	if status != http.StatusOK {
		return 0, false, ErrBackendUnavailable
	}
	size, err = verifyCollection(data)
	if err != nil {
		return 0, false, err
	}
	b.verified[collection] = size
	return size, true, nil
}

// verifyCollection accepts exactly one unnamed dense Cosine vector and
// returns its size.
func verifyCollection(data []byte) (int, error) {
	var info struct {
		Result struct {
			Config struct {
				Params struct {
					Vectors       map[string]json.RawMessage `json:"vectors"`
					SparseVectors map[string]json.RawMessage `json:"sparse_vectors"`
				} `json:"params"`
			} `json:"config"`
		} `json:"result"`
	}
	if json.Unmarshal(data, &info) != nil {
		return 0, ErrBackendUnavailable
	}
	p := info.Result.Config.Params
	if len(p.SparseVectors) > 0 {
		return 0, ErrCollectionConfig
	}
	rawSize, hasSize := p.Vectors["size"]
	rawDist, hasDist := p.Vectors["distance"]
	if !hasSize || !hasDist {
		return 0, ErrCollectionConfig // named or multi-vector layout
	}
	if _, multi := p.Vectors["multivector_config"]; multi {
		return 0, ErrCollectionConfig
	}
	if rawType, ok := p.Vectors["datatype"]; ok {
		var dt string
		if json.Unmarshal(rawType, &dt) != nil || !strings.EqualFold(dt, "float32") {
			return 0, ErrCollectionConfig
		}
	}
	var size int
	var dist string
	if json.Unmarshal(rawSize, &size) != nil || json.Unmarshal(rawDist, &dist) != nil {
		return 0, ErrCollectionConfig
	}
	if !strings.EqualFold(dist, "Cosine") {
		return 0, ErrCollectionConfig
	}
	return size, nil
}

// qdrantPayload keeps the caller's id and metadata under distinct keys.
type qdrantPayload struct {
	Text     string          `json:"text"`
	CallerID string          `json:"caller_id,omitempty"`
	Metadata json.RawMessage `json:"metadata,omitempty"`
}

func (b *qdrantBackend) Upsert(ctx context.Context, collection, id, callerID string, vec []float32, text string, meta json.RawMessage) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.probe(ctx); err != nil {
		return err
	}
	if err := b.ensureCollection(ctx, collection, len(vec)); err != nil {
		return err
	}
	type point struct {
		ID      string        `json:"id"`
		Vector  []float32     `json:"vector"`
		Payload qdrantPayload `json:"payload"`
	}
	status, data, err := b.do(ctx, http.MethodPut, collectionPath(collection)+"/points?wait=true",
		map[string]any{"points": []point{{ID: id, Vector: vec, Payload: qdrantPayload{Text: text, CallerID: callerID, Metadata: meta}}}})
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		delete(b.verified, collection) // deleted out of band: re-verify next call
	}
	if status == http.StatusBadRequest && bytes.Contains(bytes.ToLower(data), []byte("dimension")) {
		return ErrDimensionMismatch
	}
	if status != http.StatusOK {
		return ErrBackendUnavailable
	}
	return nil
}

func (b *qdrantBackend) Search(ctx context.Context, collection string, vec []float32, k int) ([]Hit, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.probe(ctx); err != nil {
		return nil, err
	}
	size, ok := b.verified[collection]
	if !ok {
		var found bool
		var err error
		if size, found, err = b.readCollection(ctx, collection); err != nil {
			return nil, err
		} else if !found {
			return nil, nil
		}
	}
	if size != len(vec) {
		return nil, ErrDimensionMismatch
	}
	status, data, err := b.do(ctx, http.MethodPost, collectionPath(collection)+"/points/query",
		map[string]any{
			"query":        vec,
			"limit":        k,
			"with_payload": true,
			"params":       map[string]any{"exact": true},
		})
	if err != nil {
		return nil, err
	}
	switch {
	case status == http.StatusNotFound:
		delete(b.verified, collection)
		return nil, nil
	case status == http.StatusBadRequest && bytes.Contains(bytes.ToLower(data), []byte("dimension")):
		return nil, ErrDimensionMismatch
	case status != http.StatusOK:
		return nil, ErrBackendUnavailable
	}
	var out struct {
		Result struct {
			Points []struct {
				ID      string        `json:"id"`
				Score   float32       `json:"score"`
				Payload qdrantPayload `json:"payload"`
			} `json:"points"`
		} `json:"result"`
	}
	if json.Unmarshal(data, &out) != nil {
		return nil, ErrBackendUnavailable
	}
	hits := make([]Hit, 0, len(out.Result.Points))
	for _, p := range out.Result.Points {
		hits = append(hits, Hit{ID: p.ID, Score: p.Score, Text: p.Payload.Text, Metadata: p.Payload.Metadata})
	}
	return hits, nil
}
