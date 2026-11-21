package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type recReq struct {
	Method, Path, RawQuery, Body string
}

// qdrantStub is a recording fake Qdrant. collectionCfg is the "vectors"
// object returned when the collection is read back.
type qdrantStub struct {
	mu            sync.Mutex
	reqs          []recReq
	rootBody      string
	collectionCfg string
	searchStatus  int
	getStatus     int    // collection GET status, default 200
	getBody       string // full collection GET body override
	searchBody    string
	srv           *httptest.Server
}

func newQdrantStub(t *testing.T) *qdrantStub {
	t.Helper()
	s := &qdrantStub{
		rootBody:      `{"title":"qdrant - vector search engine","version":"1.12.0"}`,
		collectionCfg: `{"size":3,"distance":"Cosine"}`,
		searchStatus:  200,
		getStatus:     200,
		searchBody:    `{"result":{"points":[]}}`,
	}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.reqs = append(s.reqs, recReq{r.Method, r.URL.EscapedPath(), r.URL.RawQuery, string(b)})
		s.mu.Unlock()
		p := r.URL.EscapedPath()
		switch {
		case p == "/":
			_, _ = io.WriteString(w, s.rootBody)
		case strings.HasSuffix(p, "/points/query"):
			w.WriteHeader(s.searchStatus)
			_, _ = io.WriteString(w, s.searchBody)
		case strings.HasSuffix(p, "/points"):
			_, _ = io.WriteString(w, `{"result":{"status":"completed"}}`)
		case r.Method == http.MethodPut:
			_, _ = io.WriteString(w, `{"result":true}`)
		case r.Method == http.MethodGet:
			w.WriteHeader(s.getStatus)
			if s.getBody != "" {
				_, _ = io.WriteString(w, s.getBody)
				return
			}
			_, _ = io.WriteString(w, `{"result":{"config":{"params":{"vectors":`+s.collectionCfg+`}}}}`)
		}
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *qdrantStub) count(method, path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.reqs {
		if r.Method == method && r.Path == path {
			n++
		}
	}
	return n
}

func (s *qdrantStub) find(method, suffix string) (recReq, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.reqs {
		if r.Method == method && strings.HasSuffix(r.Path, suffix) {
			return r, true
		}
	}
	return recReq{}, false
}

func (s *qdrantStub) total() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.reqs)
}

func upsertOne(b *qdrantBackend, coll string) error {
	return b.Upsert(context.Background(), coll, "11111111-1111-4111-8111-111111111111", "caller-1",
		[]float32{1, 0, 0}, "hello", json.RawMessage(`{"k": "v"}`))
}

func TestQdrantRejectsUnsafeURL(t *testing.T) {
	for _, bad := range []string{
		"http://u:p@h:6333", "http://h:6333/?x=1", "http://h:6333/#f", "http://h:6333?",
		"ftp://h:6333", "file:///x", "h:6333", "http://",
	} {
		if _, err := newQdrantBackend(bad, ""); err == nil {
			t.Fatalf("%q must be refused", bad)
		}
	}
	if _, err := newQdrantBackend("http://127.0.0.1:6333/", ""); err != nil {
		t.Fatalf("valid url refused: %v", err)
	}
}

func TestQdrantRefusesRedirect(t *testing.T) {
	var mu sync.Mutex
	hits := 0
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
	}))
	defer target.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redir.Close()
	b, err := newQdrantBackend(redir.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := upsertOne(b, "c"); !errors.Is(err, ErrBackendUnavailable) {
		t.Fatalf("got %v, want ErrBackendUnavailable", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 0 {
		t.Fatalf("redirect was followed (%d hits)", hits)
	}
}

func TestQdrantRootProbed(t *testing.T) {
	s := newQdrantStub(t)
	b, _ := newQdrantBackend(s.srv.URL, "")
	if s.total() != 0 {
		t.Fatal("constructor must not touch the network")
	}
	for i := 0; i < 2; i++ {
		if err := upsertOne(b, "c"); err != nil {
			t.Fatal(err)
		}
	}
	if n := s.count("GET", "/"); n != 1 {
		t.Fatalf("root probed %d times, want 1", n)
	}

	bad := newQdrantStub(t)
	bad.rootBody = `<html>not qdrant</html>`
	b2, _ := newQdrantBackend(bad.srv.URL, "")
	if err := upsertOne(b2, "c"); !errors.Is(err, ErrBackendUnavailable) {
		t.Fatalf("non-Qdrant root: got %v", err)
	}
	if _, err := b2.Search(context.Background(), "c", []float32{1, 0, 0}, 1); !errors.Is(err, ErrBackendUnavailable) {
		t.Fatalf("non-Qdrant root search: got %v", err)
	}
}

func TestQdrantCreatesCosineAndVerifies(t *testing.T) {
	s := newQdrantStub(t)
	b, _ := newQdrantBackend(s.srv.URL, "")
	if err := upsertOne(b, "notes"); err != nil {
		t.Fatal(err)
	}
	create, ok := s.find("PUT", "/collections/notes")
	if !ok || !strings.Contains(create.Body, `"distance":"Cosine"`) || !strings.Contains(create.Body, `"size":3`) {
		t.Fatalf("create request: %+v", create)
	}
	if s.count("GET", "/collections/notes") != 1 {
		t.Fatal("collection was not read back")
	}
	pts, ok := s.find("PUT", "/collections/notes/points")
	if !ok || pts.RawQuery != "wait=true" {
		t.Fatalf("points request: %+v", pts)
	}
	var body struct {
		Points []struct {
			ID      string
			Vector  []float32
			Payload struct {
				Text     string
				CallerID string `json:"caller_id"`
				Metadata json.RawMessage
			}
		}
	}
	if err := json.Unmarshal([]byte(pts.Body), &body); err != nil {
		t.Fatal(err)
	}
	p := body.Points[0]
	if p.ID != "11111111-1111-4111-8111-111111111111" || p.Payload.Text != "hello" ||
		p.Payload.CallerID != "caller-1" || string(p.Payload.Metadata) != `{"k":"v"}` {
		t.Fatalf("point: %+v", p)
	}
	// A second upsert reuses the verified collection: no second read-back.
	if err := upsertOne(b, "notes"); err != nil {
		t.Fatal(err)
	}
	if s.count("GET", "/collections/notes") != 1 {
		t.Fatal("verification not cached")
	}
}

func TestQdrantAlreadyExistsIsSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			_, _ = io.WriteString(w, `{"title":"qdrant - vector search engine"}`)
		case r.Method == "PUT" && r.URL.Path == "/collections/c":
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, `{"status":{"error":"Wrong input: Collection c already exists!"}}`)
		case r.Method == "GET":
			_, _ = io.WriteString(w, `{"result":{"config":{"params":{"vectors":{"size":3,"distance":"Cosine"}}}}}`)
		default:
			_, _ = io.WriteString(w, `{"result":{}}`)
		}
	}))
	defer srv.Close()
	b, _ := newQdrantBackend(srv.URL, "")
	if err := upsertOne(b, "c"); err != nil {
		t.Fatal(err)
	}
}

func TestQdrantRejectsWrongDistanceOrNamedVectors(t *testing.T) {
	cases := map[string]string{
		"dot":    `{"size":3,"distance":"Dot"}`,
		"named":  `{"dense":{"size":3,"distance":"Cosine"}}`,
		"multi":  `{"a":{"size":3,"distance":"Cosine"},"b":{"size":3,"distance":"Cosine"}}`,
		"euclid": `{"size":3,"distance":"Euclid"}`,
	}
	for name, cfg := range cases {
		s := newQdrantStub(t)
		s.collectionCfg = cfg
		b, _ := newQdrantBackend(s.srv.URL, "")
		if err := upsertOne(b, "c"); !errors.Is(err, ErrCollectionConfig) {
			t.Fatalf("%s: got %v, want ErrCollectionConfig", name, err)
		}
		if _, ok := s.find("PUT", "/collections/c/points"); ok {
			t.Fatalf("%s: wrote points to an unverified collection", name)
		}
	}
}

func TestQdrantDimensionMismatch(t *testing.T) {
	s := newQdrantStub(t)
	s.collectionCfg = `{"size":8,"distance":"Cosine"}`
	b, _ := newQdrantBackend(s.srv.URL, "")
	if err := upsertOne(b, "c"); !errors.Is(err, ErrDimensionMismatch) {
		t.Fatalf("got %v", err)
	}
}

func TestQdrantUnknownCollectionEmpty(t *testing.T) {
	s := newQdrantStub(t)
	s.searchStatus = 404
	s.searchBody = `{"status":{"error":"Not found: Collection x doesn't exist!"}}`
	b, _ := newQdrantBackend(s.srv.URL, "")
	hits, err := b.Search(context.Background(), "x", []float32{1, 0, 0}, 3)
	if err != nil || len(hits) != 0 {
		t.Fatalf("hits=%v err=%v", hits, err)
	}
}

func TestQdrantCollectionPathEscaped(t *testing.T) {
	s := newQdrantStub(t)
	b, _ := newQdrantBackend(s.srv.URL, "")
	if _, err := b.Search(context.Background(), "a b/c", []float32{1, 0, 0}, 1); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.find("POST", "/collections/a%20b%2Fc/points/query"); !ok {
		t.Fatalf("escaped path not seen: %+v", s.reqs)
	}
}

func TestQdrantSearchRoundTrip(t *testing.T) {
	s := newQdrantStub(t)
	s.searchBody = `{"result":{"points":[{"id":"11111111-1111-4111-8111-111111111111","score":0.8123457,
	  "payload":{"text":"hello","caller_id":"c1","metadata":{"k":"v"}}},
	  {"id":"22222222-2222-4222-8222-222222222222","score":0.5,"payload":{"text":"bye"}}]}}`
	b, _ := newQdrantBackend(s.srv.URL, "")
	hits, err := b.Search(context.Background(), "c", []float32{1, 0, 0}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 2 || hits[0].ID != "11111111-1111-4111-8111-111111111111" || hits[0].Score != float32(0.8123457) ||
		hits[0].Text != "hello" || string(hits[0].Metadata) != `{"k":"v"}` || hits[1].Metadata != nil {
		t.Fatalf("hits: %+v", hits)
	}
	req, _ := s.find("POST", "/points/query")
	var body map[string]any
	if err := json.Unmarshal([]byte(req.Body), &body); err != nil {
		t.Fatal(err)
	}
	params, _ := body["params"].(map[string]any)
	if body["limit"] != float64(2) || body["with_payload"] != true || params["exact"] != true {
		t.Fatalf("query body: %s", req.Body)
	}
}

func TestQdrantSendsAPIKey(t *testing.T) {
	t.Setenv("QDRANT_TEST_KEY", "sekret")
	var mu sync.Mutex
	got := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = r.Header.Get("api-key")
		mu.Unlock()
		_, _ = io.WriteString(w, `{"title":"qdrant"}`)
	}))
	defer srv.Close()
	b, _ := newQdrantBackend(srv.URL, "QDRANT_TEST_KEY")
	if err := b.probe(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if got != "sekret" {
		t.Fatalf("api-key header %q", got)
	}
}

func TestQdrantSearchVerifiesUncachedCollection(t *testing.T) {
	for name, cfg := range map[string]string{
		"dot":   `{"size":3,"distance":"Dot"}`,
		"named": `{"dense":{"size":3,"distance":"Cosine"}}`,
	} {
		s := newQdrantStub(t)
		s.collectionCfg = cfg
		b, _ := newQdrantBackend(s.srv.URL, "")
		if _, err := b.Search(context.Background(), "c", []float32{1, 0, 0}, 1); !errors.Is(err, ErrCollectionConfig) {
			t.Fatalf("%s: got %v, want ErrCollectionConfig", name, err)
		}
		if _, ok := s.find("POST", "/points/query"); ok {
			t.Fatalf("%s: queried an unverified collection", name)
		}
	}
	s := newQdrantStub(t)
	s.getStatus = 404
	b, _ := newQdrantBackend(s.srv.URL, "")
	hits, err := b.Search(context.Background(), "missing", []float32{1, 0, 0}, 1)
	if err != nil || len(hits) != 0 {
		t.Fatalf("missing: hits=%v err=%v", hits, err)
	}
	if _, ok := s.find("POST", "/points/query"); ok {
		t.Fatal("queried a missing collection")
	}
	// A verified Search is cached: the second call does not re-read.
	s2 := newQdrantStub(t)
	b2, _ := newQdrantBackend(s2.srv.URL, "")
	for i := 0; i < 2; i++ {
		if _, err := b2.Search(context.Background(), "c", []float32{1, 0, 0}, 1); err != nil {
			t.Fatal(err)
		}
	}
	if s2.count("GET", "/collections/c") != 1 {
		t.Fatal("search verification not cached")
	}
	if _, err := b2.Search(context.Background(), "c", []float32{1, 0}, 1); !errors.Is(err, ErrDimensionMismatch) {
		t.Fatalf("dim: got %v", err)
	}
}

func TestQdrantRejectsMultivectorDatatypeSparse(t *testing.T) {
	cases := map[string]string{
		"multivector": `{"result":{"config":{"params":{"vectors":{"size":3,"distance":"Cosine","multivector_config":{"comparator":"max_sim"}}}}}}`,
		"uint8":       `{"result":{"config":{"params":{"vectors":{"size":3,"distance":"Cosine","datatype":"uint8"}}}}}`,
		"sparse":      `{"result":{"config":{"params":{"vectors":{"size":3,"distance":"Cosine"},"sparse_vectors":{"s":{}}}}}}`,
	}
	for name, body := range cases {
		s := newQdrantStub(t)
		s.getBody = body
		b, _ := newQdrantBackend(s.srv.URL, "")
		if err := upsertOne(b, "c"); !errors.Is(err, ErrCollectionConfig) {
			t.Fatalf("%s: got %v, want ErrCollectionConfig", name, err)
		}
	}
	s := newQdrantStub(t)
	s.getBody = `{"result":{"config":{"params":{"vectors":{"size":3,"distance":"Cosine","datatype":"float32"}}}}}`
	b, _ := newQdrantBackend(s.srv.URL, "")
	if err := upsertOne(b, "c"); err != nil {
		t.Fatalf("float32 datatype refused: %v", err)
	}
}

func TestQdrantUpsert404EvictsVerification(t *testing.T) {
	var mu sync.Mutex
	gone, gets := false, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.URL.Path == "/":
			_, _ = io.WriteString(w, `{"title":"qdrant"}`)
		case r.Method == "PUT" && strings.HasSuffix(r.URL.Path, "/points") && gone:
			w.WriteHeader(http.StatusNotFound)
		case r.Method == "GET":
			gets++
			_, _ = io.WriteString(w, `{"result":{"config":{"params":{"vectors":{"size":3,"distance":"Cosine"}}}}}`)
		default:
			_, _ = io.WriteString(w, `{"result":{}}`)
		}
	}))
	defer srv.Close()
	b, _ := newQdrantBackend(srv.URL, "")
	if err := upsertOne(b, "c"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	gone = true
	mu.Unlock()
	if err := upsertOne(b, "c"); !errors.Is(err, ErrBackendUnavailable) {
		t.Fatalf("got %v", err)
	}
	mu.Lock()
	gone = false
	mu.Unlock()
	if err := upsertOne(b, "c"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if gets != 2 {
		t.Fatalf("collection read %d times, want 2 (re-verified after 404)", gets)
	}
}

func TestQdrantNoProxy(t *testing.T) {
	b, _ := newQdrantBackend("http://127.0.0.1:6333", "")
	tr, ok := b.client.Transport.(*http.Transport)
	if !ok || tr.Proxy != nil {
		t.Fatal("transport must have Proxy == nil")
	}
	if b.client.CheckRedirect == nil {
		t.Fatal("redirects must be refused")
	}
}

func TestQdrantSearchSends(t *testing.T) {
	s := newQdrantStub(t)
	b, _ := newQdrantBackend(s.srv.URL, "")
	if _, err := b.Search(context.Background(), "c", []float32{0.5, 0.25, 1}, 4); err != nil {
		t.Fatal(err)
	}
	req, _ := s.find("POST", "/points/query")
	var body struct {
		Query []float32 `json:"query"`
	}
	if err := json.Unmarshal([]byte(req.Body), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Query) != 3 || body.Query[0] != 0.5 || body.Query[1] != 0.25 || body.Query[2] != 1 {
		t.Fatalf("query vector: %s", req.Body)
	}
}

func TestQdrantSearchBadDimensionResponse(t *testing.T) {
	s := newQdrantStub(t)
	s.searchStatus = 400
	s.searchBody = `{"status":{"error":"Wrong input: Vector dimension error: expected dim: 3, got 2"}}`
	b, _ := newQdrantBackend(s.srv.URL, "")
	if _, err := b.Search(context.Background(), "c", []float32{1, 0, 0}, 1); !errors.Is(err, ErrDimensionMismatch) {
		t.Fatalf("got %v", err)
	}
}
