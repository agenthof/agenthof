package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/agenthof/agenthof/deploy/internal/confiner"
	"github.com/agenthof/agenthof/deploy/internal/confiner/confinertest"
)

var testHash = "sha256:" + strings.Repeat("cd", 32)

// bindConfiner is a Confiner over the fake that records each launch's
// Spec.Expected, serves each agent's socket itself (the fake would exec the
// socket flag), and can refuse with ErrArtifactMismatch or report a measured
// artifact — the supervisor-side behavior of the binding, without a backend.
type bindConfiner struct {
	*confinertest.Fake
	mu       sync.Mutex
	expected map[string]*confiner.ExpectedArtifact // by compartment name
	mismatch bool
	ran      *confiner.ExpectedArtifact
}

func (b *bindConfiner) Launch(_ context.Context, spec confiner.Spec) (confiner.Compartment, error) {
	b.mu.Lock()
	b.expected[spec.Name] = spec.Expected
	mismatch, ran := b.mismatch, b.ran
	b.mu.Unlock()
	if mismatch {
		return nil, confiner.ErrArtifactMismatch
	}
	ln, err := net.Listen("unix", spec.Argv[1])
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return &bindCompartment{ln: ln, ran: ran, done: make(chan struct{})}, nil
}

type bindCompartment struct {
	ln   net.Listener
	ran  *confiner.ExpectedArtifact
	once sync.Once
	done chan struct{}
}

func (c *bindCompartment) Wait(context.Context) (confiner.Result, error) {
	<-c.done
	return confiner.Result{}, nil
}
func (c *bindCompartment) Done() <-chan struct{} { return c.done }
func (c *bindCompartment) PID() int              { return 1 }
func (c *bindCompartment) Remove(context.Context) error {
	c.once.Do(func() { _ = c.ln.Close(); close(c.done) })
	return nil
}
func (c *bindCompartment) RanArtifact() (string, []string, bool) {
	if c.ran == nil {
		return "", nil, false
	}
	return c.ran.Kind, c.ran.Values, true
}

func bindSupervisor(t *testing.T, tier confiner.Tier, agents ...string) (*supervisor, *httptest.Server, *bindConfiner) {
	t.Helper()
	cfg := testConfig(t, selfImages(t, agents...))
	if err := os.MkdirAll(cfg.SpawnRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	fake := confinertest.New(t.TempDir())
	fake.TierName = tier
	bc := &bindConfiner{Fake: fake, expected: map[string]*confiner.ExpectedArtifact{}}
	s := newSupervisor(cfg, slog.New(slog.DiscardHandler), bc)
	srv := httptest.NewServer(s.handler())
	t.Cleanup(srv.Close)
	return s, srv, bc
}

// provisionExpected POSTs a request carrying expected and returns the status
// and, on 200, the held response with its first line.
func provisionExpected(t *testing.T, srv *httptest.Server, id string, agents []string, expected map[string][]wireExpected) (int, *http.Response, provisionLine) {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"child_run_id": id, "agents": agents, "expected": expected})
	resp, err := srv.Client().Post(srv.URL+"/provision", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST /provision: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return resp.StatusCode, nil, provisionLine{}
	}
	raw, err := bufio.NewReader(resp.Body).ReadBytes('\n')
	if err != nil {
		t.Fatalf("first line: %v", err)
	}
	var line provisionLine
	if err := json.Unmarshal(raw, &line); err != nil {
		t.Fatalf("first line %q: %v", raw, err)
	}
	return resp.StatusCode, resp, line
}

func TestProvisionPassesTheTierKindFormAndReportsRan(t *testing.T) {
	for _, tc := range []struct {
		tier confiner.Tier
		kind string
	}{{confiner.TierPodman, "oci-image"}, {confiner.TierSeatbelt, "host-program"}} {
		_, srv, bc := bindSupervisor(t, tc.tier, "a", "b")
		bc.ran = &confiner.ExpectedArtifact{Kind: tc.kind, Values: []string{testHash}}
		other := "sha256:" + strings.Repeat("ee", 32)
		code, resp, line := provisionExpected(t, srv, "r-0a0b0c0d", []string{"a", "b"}, map[string][]wireExpected{
			"a": {{Kind: "oci-image", Values: []string{testHash}}, {Kind: "host-program", Values: []string{other}}},
		})
		if code != http.StatusOK {
			t.Fatalf("%s: code = %d", tc.tier, code)
		}
		want := testHash
		if tc.kind == "host-program" {
			want = other
		}
		bc.mu.Lock()
		gotA, gotB := bc.expected[compartmentName("r-0a0b0c0d", "a")], bc.expected[compartmentName("r-0a0b0c0d", "b")]
		bc.mu.Unlock()
		if gotA == nil || gotA.Kind != tc.kind || len(gotA.Values) != 1 || gotA.Values[0] != want {
			t.Fatalf("%s: agent a Spec.Expected = %+v, want kind %s value %s", tc.tier, gotA, tc.kind, want)
		}
		if gotB != nil {
			t.Fatalf("%s: agent b has no expected entry (non-provenance): Spec.Expected must be nil, got %+v", tc.tier, gotB)
		}
		for _, a := range []string{"a", "b"} {
			r, ok := line.Ran[a]
			if !ok || r.Kind != tc.kind || len(r.Values) != 1 || r.Values[0] != testHash {
				t.Fatalf("%s: line.Ran[%s] = %+v ok=%v, want the measured artifact", tc.tier, a, r, ok)
			}
		}
		_ = resp.Body.Close()
	}
}

func TestProvisionOmitsRanWhenNothingMeasured(t *testing.T) {
	_, srv, _ := bindSupervisor(t, confiner.TierPodman, "a")
	code, resp, line := provisionExpected(t, srv, "r-0a0b0c0d", []string{"a"}, nil)
	if code != http.StatusOK {
		t.Fatalf("code = %d", code)
	}
	defer func() { _ = resp.Body.Close() }()
	if len(line.Ran) != 0 {
		t.Fatalf("Ran = %+v, want none from an agent that measured nothing", line.Ran)
	}
}

func TestLaunchMismatchIsTheBindingStatus(t *testing.T) {
	s, srv, bc := bindSupervisor(t, confiner.TierPodman, "a")
	bc.mismatch = true
	code, _, _ := provisionExpected(t, srv, "r-0a0b0c0d", []string{"a"}, map[string][]wireExpected{
		"a": {{Kind: "oci-image", Values: []string{testHash}}},
	})
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("a confiner artifact mismatch: code = %d, want 422", code)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used != 0 || s.live["r-0a0b0c0d"] {
		t.Fatalf("a refused set must release its slots (used=%d)", s.used)
	}
}

func TestExpectedWithoutTheTierKindIsRefusedBeforeStart(t *testing.T) {
	s, srv, bc := bindSupervisor(t, confiner.TierPodman, "a", "b")
	// b has forms, but none of this tier's kind: the whole set is refused.
	code, _, _ := provisionExpected(t, srv, "r-0a0b0c0d", []string{"a", "b"}, map[string][]wireExpected{
		"a": {{Kind: "oci-image", Values: []string{testHash}}},
		"b": {{Kind: "host-program", Values: []string{testHash}}},
	})
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("no form for the tier's kind: code = %d, want 422", code)
	}
	bc.mu.Lock()
	launched := len(bc.expected)
	bc.mu.Unlock()
	if launched != 0 || len(bc.OpsSnapshot()) != 0 {
		t.Fatalf("nothing may start (launches=%d ops=%v)", launched, bc.OpsSnapshot())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used != 0 {
		t.Fatalf("used = %d, want 0", s.used)
	}
	// An unknown tier has no kind: an agent with forms has none that match.
	_, srv2, _ := bindSupervisor(t, "wsl2", "a")
	code, _, _ = provisionExpected(t, srv2, "r-0a0b0c0d", []string{"a"}, map[string][]wireExpected{
		"a": {{Kind: "oci-image", Values: []string{testHash}}},
	})
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("unknown tier with expected forms: code = %d, want 422", code)
	}
}

func TestMissingImageStaysForbidden(t *testing.T) {
	_, srv, _ := bindSupervisor(t, confiner.TierPodman, "a")
	code, _, _ := provisionExpected(t, srv, "r-0a0b0c0d", []string{"a", "ghost"}, map[string][]wireExpected{
		"ghost": {{Kind: "oci-image", Values: []string{testHash}}},
	})
	if code != http.StatusForbidden {
		t.Fatalf("an agent with no image: code = %d, want 403 (not the binding status)", code)
	}
}
