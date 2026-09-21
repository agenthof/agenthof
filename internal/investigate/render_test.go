package investigate

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// mkSource is a small literal-builder to keep the ExitCode table compact.
func mkSource(kind, path, integrity string, count int) Source {
	return Source{Path: path, Kind: kind, Integrity: integrity, Count: count}
}

func TestExitCode(t *testing.T) {
	cases := []struct {
		name string
		r    Result
		want int
	}{
		{
			name: "all verified",
			r: Result{Sources: []Source{
				mkSource("run", "/logs/r-1.jsonl", "verified", 2),
				mkSource("control", "/logs/control.jsonl", "verified", 1),
			}},
			want: 0,
		},
		{name: "empty result", r: Result{}, want: 0},
		{
			name: "one torn",
			r:    Result{Sources: []Source{mkSource("run", "/logs/r-1.jsonl", "torn", 2)}},
			want: 1,
		},
		{
			name: "one error",
			r:    Result{Sources: []Source{mkSource("run", "/logs/r-1.jsonl", "error", 0)}},
			want: 1,
		},
		{
			name: "tainted only",
			r:    Result{Sources: []Source{mkSource("control", "/logs/control.jsonl", "tainted", 1)}},
			want: 3,
		},
		{
			name: "tainted plus broken takes precedence",
			r: Result{Sources: []Source{
				mkSource("control", "/logs/control.jsonl", "tainted", 1),
				mkSource("run", "/logs/r-2.jsonl", "broken", 3),
			}},
			want: 1,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ExitCode(c.r); got != c.want {
				t.Fatalf("ExitCode = %d, want %d", got, c.want)
			}
		})
	}
}

func TestRenderJSONShapeAndQuery(t *testing.T) {
	// tm is UTC noon; feeding a non-UTC representation of the SAME instants
	// into events and the filter proves RenderJSON actually normalizes to
	// UTC rather than passing through values that already happened to be UTC.
	tm := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	plusOne := time.FixedZone("plus1", 3600)
	r := Result{
		Events: []Record{
			{
				Time:    tm.In(plusOne),
				Source:  "run",
				RunID:   "r-1",
				Kind:    "step_started",
				Invoker: Invoker{Subject: "dana@example.com", Issuer: "static", Method: "static"},
				Agent:   "coder",
				Outcome: "success",
			},
		},
		Sources: []Source{mkSource("run", "/logs/r-1.jsonl", "verified", 1)},
	}
	since := tm.Add(-time.Hour).In(plusOne)
	f := Filter{Agent: "coder", Since: &since}

	out, err := RenderJSON(r, f)
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	if strings.Contains(out, "witness") {
		t.Fatalf("output must never contain a witness field:\n%s", out)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, out)
	}

	if parsed["v"] != "investigate/1" {
		t.Fatalf("v = %v, want investigate/1", parsed["v"])
	}

	integrity, ok := parsed["integrity"].(map[string]any)
	if !ok {
		t.Fatalf("integrity missing or wrong shape: %+v", parsed)
	}
	wantOK := ExitCode(r) == 0
	if integrity["ok"] != wantOK {
		t.Fatalf("integrity.ok = %v, want %v", integrity["ok"], wantOK)
	}

	query, ok := parsed["query"].(map[string]any)
	if !ok {
		t.Fatalf("query missing or wrong shape: %+v", parsed)
	}
	if len(query) != 2 {
		t.Fatalf("query = %+v, want exactly {agent, since} (only set filters)", query)
	}
	if query["agent"] != "coder" {
		t.Fatalf("query.agent = %v, want coder", query["agent"])
	}
	if _, present := query["since"]; !present {
		t.Fatalf("query.since missing: %+v", query)
	}
	if query["since"] != "2026-09-21T11:00:00Z" {
		t.Fatalf("query.since = %v, want 2026-09-21T11:00:00Z (RFC3339 UTC, normalized from a non-UTC input)", query["since"])
	}
	for _, unset := range []string{"until", "invoker", "outcome", "run", "config_hash"} {
		if _, present := query[unset]; present {
			t.Fatalf("query.%s must be absent when unset: %+v", unset, query)
		}
	}

	events, ok := parsed["events"].([]any)
	if !ok || len(events) != 1 {
		t.Fatalf("events = %+v, want exactly one event", parsed["events"])
	}
	ev, ok := events[0].(map[string]any)
	if !ok {
		t.Fatalf("event[0] wrong shape: %+v", events[0])
	}
	if ev["kind"] != "step_started" {
		t.Fatalf("event.kind = %v, want step_started", ev["kind"])
	}
	if ev["time"] != "2026-09-21T12:00:00Z" {
		t.Fatalf("event.time = %v, want RFC3339 UTC", ev["time"])
	}
	inv, ok := ev["invoker"].(map[string]any)
	if !ok || inv["subject"] != "dana@example.com" {
		t.Fatalf("event.invoker = %+v, want subject dana@example.com", ev["invoker"])
	}

	sources, ok := parsed["sources"].([]any)
	if !ok || len(sources) != 1 {
		t.Fatalf("sources = %+v, want exactly one source", parsed["sources"])
	}
}

func TestRenderJSONIntegrityOKMatchesExitCode(t *testing.T) {
	cases := []struct {
		name string
		r    Result
	}{
		{name: "clean", r: Result{Sources: []Source{mkSource("run", "/logs/r-1.jsonl", "verified", 1)}}},
		{name: "torn", r: Result{Sources: []Source{mkSource("run", "/logs/r-1.jsonl", "torn", 1)}}},
		{name: "tainted", r: Result{Sources: []Source{mkSource("control", "/logs/control.jsonl", "tainted", 1)}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := RenderJSON(c.r, Filter{})
			if err != nil {
				t.Fatalf("RenderJSON: %v", err)
			}
			var parsed struct {
				Integrity struct {
					OK     bool     `json:"ok"`
					Issues []string `json:"issues"`
				} `json:"integrity"`
			}
			if err := json.Unmarshal([]byte(out), &parsed); err != nil {
				t.Fatalf("unmarshal: %v\n%s", err, out)
			}
			want := ExitCode(c.r) == 0
			if parsed.Integrity.OK != want {
				t.Fatalf("integrity.ok = %v, want %v (ExitCode=%d)", parsed.Integrity.OK, want, ExitCode(c.r))
			}
			if want && len(parsed.Integrity.Issues) != 0 {
				t.Fatalf("issues should be empty when ok, got %v", parsed.Integrity.Issues)
			}
			if !want && len(parsed.Integrity.Issues) == 0 {
				t.Fatalf("issues should be non-empty when not ok")
			}
		})
	}
}

func TestRenderTextSmoke(t *testing.T) {
	tm := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	r := Result{
		Events: []Record{
			{
				Time:    tm,
				Source:  "run",
				RunID:   "r-1",
				Kind:    "step_started",
				Invoker: Invoker{Subject: "dana@example.com", Method: "static"},
				Agent:   "coder",
				Outcome: "success",
			},
		},
		Sources: []Source{mkSource("run", "/logs/r-1.jsonl", "verified", 1)},
	}
	text := RenderText(r)

	if !strings.Contains(text, "investigation timeline") {
		t.Fatalf("expected a header line, got:\n%s", text)
	}
	if !strings.Contains(text, "/logs/r-1.jsonl") || !strings.Contains(text, "verified") {
		t.Fatalf("expected a per-source summary line naming path and integrity, got:\n%s", text)
	}
	if !strings.Contains(text, "dana@example.com") || !strings.Contains(text, "static") {
		t.Fatalf("expected an event line with subject and method, got:\n%s", text)
	}
	if !strings.Contains(text, "coder") || !strings.Contains(text, "success") {
		t.Fatalf("expected the event line to carry agent/outcome, got:\n%s", text)
	}
	if !strings.Contains(text, "integrity: OK") {
		t.Fatalf("expected a trailing OK integrity line, got:\n%s", text)
	}
}

func TestRenderTextNamesTornProblem(t *testing.T) {
	r := Result{
		Sources: []Source{mkSource("run", "/logs/r-torn.jsonl", "torn", 1)},
	}
	text := RenderText(r)
	if !strings.Contains(text, "integrity: run r-torn TORN") {
		t.Fatalf("expected the trailing integrity line to name the torn source, got:\n%s", text)
	}
	if strings.Contains(text, "integrity: OK") {
		t.Fatalf("a torn source must not report integrity: OK, got:\n%s", text)
	}
}
