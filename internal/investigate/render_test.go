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

// TestRenderTextNoAnchorsIsByteIdentical: a view without anchors renders
// exactly what it rendered before anchors existed — no trailer, no tag.
func TestRenderTextNoAnchorsIsByteIdentical(t *testing.T) {
	tm := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	r := Result{
		Events: []Record{
			{Time: tm, Source: "control", Kind: "apply", Invoker: Invoker{Subject: "dana@example.com", Method: "asserted"}, Outcome: "success", Seq: 1},
			{Time: tm.Add(time.Second), Source: "run", RunID: "r-1", Kind: "step_started", Invoker: Invoker{Subject: "dana@example.com", Method: "static"}, Agent: "coder", Outcome: "success"},
		},
		Sources: []Source{mkSource("run", "/logs/r-1.jsonl", "verified", 1), mkSource("control", "/logs/control.jsonl", "verified", 1)},
	}
	want := "investigation timeline: 2 event(s) across 2 source(s)\n" +
		"source: run /logs/r-1.jsonl integrity=verified count=1\n" +
		"source: control /logs/control.jsonl integrity=verified count=1\n" +
		"2026-09-21T12:00:00Z control apply — dana@example.com (asserted) [outcome=success]\n" +
		"2026-09-21T12:00:01Z run step_started — dana@example.com (static) [agent=coder outcome=success]\n" +
		"integrity: OK\n"
	if got := RenderText(r); got != want {
		t.Fatalf("--- got ---\n%s--- want ---\n%s", got, want)
	}
}

// TestRenderTextAnchorTagsAndTrailer: the tags in order — anchor=, backend=,
// ref=, verdict=, cause= last — each present iff its field is; a failed
// attempt shows facts and no verdict; a planted success without a payload
// shows verdict and cause only; the trailer after the integrity line counts
// the verdicts in the view.
func TestRenderTextAnchorTagsAndTrailer(t *testing.T) {
	tm := time.Date(2026, 10, 14, 6, 0, 3, 0, time.UTC)
	hash, ref, keyID := strings.Repeat("9f", 32), strings.Repeat("24", 40), strings.Repeat("c0", 32)
	inv := Invoker{Subject: "anchor-cron@example.com", Method: "oidc"}
	cause := "the chain does not reproduce the recorded head at seq 41 (chain " + strings.Repeat("7a", 32) + ", recorded " + hash + ")"
	r := Result{
		Events: []Record{
			{Time: tm, Source: "control", Kind: "anchor", Invoker: inv, Outcome: "success", Seq: 42,
				Anchor: &Anchor{Seq: 41, Hash: hash, Kind: "tlog", BackendKind: "transparency-log", Backend: "https://rekor.example", Ref: ref, BackendKeyID: keyID, Verdict: "verified"}},
			{Time: tm.Add(time.Second), Source: "control", Kind: "anchor", Invoker: inv, Outcome: "success", Seq: 43,
				Anchor: &Anchor{Seq: 41, Hash: hash, Kind: "tlog", BackendKind: "transparency-log", Backend: "https://rekor.example", Ref: ref, BackendKeyID: keyID, Verdict: "mismatch", Cause: cause}},
			{Time: tm.Add(2 * time.Second), Source: "control", Kind: "anchor", Invoker: inv, Outcome: "error", Reason: "status 503 from rekor.example", Seq: 44,
				Anchor: &Anchor{Seq: 43, Hash: hash, Kind: "tlog", BackendKind: "transparency-log", Backend: "https://rekor.example"}},
			{Time: tm.Add(3 * time.Second), Source: "control", Kind: "anchor", Invoker: inv, Outcome: "success", Seq: 45,
				Anchor: &Anchor{Verdict: "mismatch", Cause: "anchor record without coverage"}},
			{Time: tm.Add(4 * time.Second), Source: "control", Kind: "anchor", Invoker: inv, Outcome: "success", Seq: 46,
				Anchor: &Anchor{Seq: 41, Hash: hash, Kind: "tlog", BackendKind: "transparency-log", Backend: "https://rekor.example", Ref: ref, Verdict: "unverifiable", Cause: "no key to verify under (unpinned, offline)"}},
		},
		Sources: []Source{mkSource("control", "/logs/control.jsonl", "verified", 46)},
	}
	want := "investigation timeline: 5 event(s) across 1 source(s)\n" +
		"source: control /logs/control.jsonl integrity=verified count=46\n" +
		"2026-10-14T06:00:03Z control anchor — anchor-cron@example.com (oidc) [outcome=success anchor=41:" + hash + " backend=https://rekor.example ref=" + ref + " verdict=verified]\n" +
		"2026-10-14T06:00:04Z control anchor — anchor-cron@example.com (oidc) [outcome=success anchor=41:" + hash + " backend=https://rekor.example ref=" + ref + " verdict=mismatch cause=" + cause + "]\n" +
		"2026-10-14T06:00:05Z control anchor — anchor-cron@example.com (oidc) [outcome=error reason=status 503 from rekor.example anchor=43:" + hash + " backend=https://rekor.example]\n" +
		"2026-10-14T06:00:06Z control anchor — anchor-cron@example.com (oidc) [outcome=success verdict=mismatch cause=anchor record without coverage]\n" +
		"2026-10-14T06:00:07Z control anchor — anchor-cron@example.com (oidc) [outcome=success anchor=41:" + hash + " backend=https://rekor.example ref=" + ref + " verdict=unverifiable cause=no key to verify under (unpinned, offline)]\n" +
		"integrity: OK\n" +
		"anchors: 4 (1 verified, 2 mismatch, 1 unverifiable)\n"
	if got := RenderText(r); got != want {
		t.Fatalf("--- got ---\n%s--- want ---\n%s", got, want)
	}
	if ExitCode(r) != 0 {
		t.Fatalf("a mismatch anchor never changes the exit: %d", ExitCode(r))
	}
}

// TestRenderTextTrailerCountsTornAnchors: under a torn control source the
// anchors carry unverifiable verdicts and are counted as such, below an
// integrity line that already names the damage.
func TestRenderTextTrailerCountsTornAnchors(t *testing.T) {
	r := Result{
		Events: []Record{{Time: time.Date(2026, 10, 14, 6, 0, 0, 0, time.UTC), Source: "control", Kind: "anchor", Invoker: Invoker{Subject: "dana@example.com", Method: "asserted"}, Outcome: "success", Seq: 2,
			Anchor: &Anchor{Seq: 1, Hash: strings.Repeat("ab", 32), Verdict: "unverifiable", Cause: causeTorn}}},
		Sources: []Source{mkSource("control", "/logs/control.jsonl", "torn", 2)},
	}
	text := RenderText(r)
	if !strings.HasSuffix(text, "integrity: control ledger TORN at /logs/control.jsonl\nanchors: 1 (0 verified, 0 mismatch, 1 unverifiable)\n") {
		t.Fatalf("got:\n%s", text)
	}
	if ExitCode(r) != 1 {
		t.Fatalf("exit %d", ExitCode(r))
	}
}

// TestRenderJSONAnchorIsAdditive: the anchor object marshals inside its
// event; the envelope and the sources carry no anchors key; no proof; and
// integrity.ok / issues are what the sources alone say — a mismatch anchor
// leaves ok true and issues empty.
func TestRenderJSONAnchorIsAdditive(t *testing.T) {
	r := Result{
		Events: []Record{{Time: time.Date(2026, 10, 14, 6, 0, 0, 0, time.UTC), Source: "control", Kind: "anchor", Invoker: Invoker{Subject: "dana@example.com", Method: "asserted"}, Outcome: "success", Seq: 2,
			Anchor: &Anchor{Seq: 1, Hash: strings.Repeat("ab", 32), Kind: "tlog", BackendKind: "transparency-log", Backend: "https://rekor.example", Ref: strings.Repeat("0", 80), Verdict: "mismatch", Cause: "x"}}},
		Sources: []Source{mkSource("control", "/logs/control.jsonl", "verified", 2)},
	}
	out, err := RenderJSON(r, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]json.RawMessage
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"v", "query", "sources", "events", "integrity"} {
		delete(env, k)
	}
	if len(env) != 0 {
		t.Fatalf("unexpected envelope keys: %v", env)
	}
	var parsed struct {
		Sources   []map[string]any `json:"sources"`
		Events    []map[string]any `json:"events"`
		Integrity struct {
			OK     bool     `json:"ok"`
			Issues []string `json:"issues"`
		} `json:"integrity"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatal(err)
	}
	if _, has := parsed.Sources[0]["anchors"]; has || len(parsed.Sources[0]) != 4 {
		t.Fatalf("sources must stay {path, kind, integrity, count}: %v", parsed.Sources[0])
	}
	a, ok := parsed.Events[0]["anchor"].(map[string]any)
	if !ok || a["verdict"] != "mismatch" || a["cause"] != "x" || a["seq"] != float64(1) {
		t.Fatalf("event anchor: %v", parsed.Events[0]["anchor"])
	}
	if strings.Contains(out, "proof") || strings.Contains(out, `"anchors"`) {
		t.Fatalf("no proof, no summary key:\n%s", out)
	}
	if !parsed.Integrity.OK || len(parsed.Integrity.Issues) != 0 || ExitCode(r) != 0 {
		t.Fatalf("integrity must follow the sources alone: %+v exit %d", parsed.Integrity, ExitCode(r))
	}
}
