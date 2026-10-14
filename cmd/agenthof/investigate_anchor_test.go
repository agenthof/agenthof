package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/anchor/anchortest"
	"github.com/agenthof/agenthof/internal/investigate"
	"github.com/agenthof/agenthof/internal/ledger"
)

// TestInvestigateAnchorKeyIsLocalOnly: --anchor-key with --server, or with
// AGENTHOF_SERVER set, is a usage error before any request; locally, an
// absent key is a per-anchor verdict and exit 0, never exit 2.
func TestInvestigateAnchorKeyIsLocalOnly(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	t.Setenv("AGENTHOF_SERVER", "")
	ctl, _ := anchoredViaStub(t)
	logs := t.TempDir()
	const msg = "investigate: --anchor-key is local-only; the server pins anchor.pub beside its own ledger\n"

	var out bytes.Buffer
	if code := cmdInvestigate([]string{"--log-dir", logs, "--control-log", ctl, "--anchor-key", "x.pub", "--server", "http://127.0.0.1:9"}, &out); code != 2 || out.String() != msg {
		t.Fatalf("--server: exit %d\n%s", code, out.String())
	}
	t.Setenv("AGENTHOF_SERVER", "http://127.0.0.1:9")
	out.Reset()
	if code := cmdInvestigate([]string{"--log-dir", logs, "--control-log", ctl, "--anchor-key", "x.pub"}, &out); code != 2 || out.String() != msg {
		t.Fatalf("AGENTHOF_SERVER: exit %d\n%s", code, out.String())
	}
	t.Setenv("AGENTHOF_SERVER", "")
	out.Reset()
	if code := cmdInvestigate([]string{"--log-dir", logs, "--control-log", ctl, "--anchor-key", "/nope/missing.pub"}, &out); code != 0 || !strings.Contains(out.String(), "verdict=unverifiable cause=pinned log key /nope/missing.pub: ") {
		t.Fatalf("missing key locally: exit %d\n%s", code, out.String())
	}
}

// plantSuccessAnchor appends a hand-built success anchor record with no
// payload — the shape Append refuses — chained onto the current head so the
// ledger still verifies: the record a hostile writer can plant.
func plantSuccessAnchor(t *testing.T, ctl string) {
	t.Helper()
	recs, head, err := ledger.ReadVerify(ctl, ledger.Unlocked)
	if err != nil {
		t.Fatal(err)
	}
	raw := fmt.Sprintf(`{"v":"control/1","seq":%d,"time":%q,"action":"anchor","outcome":"success","invoker":{"subject":"forger","issuer":"local","method":"asserted"},"witness":{"os_user":"forger","hostname":"elsewhere"},"prev":%q}`,
		len(recs)+1, time.Now().UTC().Format(time.RFC3339Nano), head.Hash)
	f, err := os.OpenFile(ctl, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(raw + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// gateAnchorLines returns audit verify control's per-anchor lines in order.
func gateAnchorLines(out string) []string {
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "anchor seq ") || strings.HasPrefix(l, "anchor record seq ") {
			lines = append(lines, l)
		}
	}
	return lines
}

// gateVerdict reads the verdict word and the cause off one gate line. The
// cause is everything after the first "MISMATCH — " or "unverifiable — ":
// several causes themselves contain " — ".
func gateVerdict(t *testing.T, line string) (verdict, cause string) {
	t.Helper()
	if strings.Contains(line, ": verified (") {
		return "verified", ""
	}
	if _, rest, ok := strings.Cut(line, ": MISMATCH — "); ok {
		return "mismatch", rest
	}
	if _, rest, ok := strings.Cut(line, ": unverifiable — "); ok {
		return "unverifiable", rest
	}
	t.Fatalf("unparsed gate line: %q", line)
	return "", ""
}

// TestInvestigateAndVerifyControlAgreeOnAnchors is the drift detector: for
// every anchor record, investigate's verdict word is the gate's and its cause
// is the gate's, pairing the gate's lines with investigate's success anchor
// events in chain order; the gate's exit is 6 iff any verdict is mismatch,
// 7 iff none is and any is unverifiable; investigate exits 0 throughout.
func TestInvestigateAndVerifyControlAgreeOnAnchors(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	t.Setenv("AGENTHOF_SERVER", "")
	cases := []struct {
		name   string
		mutate func(t *testing.T, ctl string, stub *anchortest.Stub)
	}{
		{"clean", func(*testing.T, string, *anchortest.Stub) {}},
		{"re-forged root", func(t *testing.T, ctl string, _ *anchortest.Stub) {
			rewriteTail(t, ctl, 1, func(int, map[string]any) {})
		}},
		{"flipped proof", func(t *testing.T, ctl string, _ *anchortest.Stub) {
			rewriteTail(t, ctl, 2, func(_ int, m map[string]any) {
				p := m["anchor"].(map[string]any)["proof"].(string)
				m["anchor"].(map[string]any)["proof"] = "A" + p[1:]
			})
		}},
		{"backend unavailable", func(_ *testing.T, _ string, stub *anchortest.Stub) { stub.Fail() }},
		{"production dispatch", func(t *testing.T, _ string, _ *anchortest.Stub) {
			prev := newAnchorBackend
			newAnchorBackend = anchorBackendFor
			t.Cleanup(func() { newAnchorBackend = prev })
		}},
		{"planted success without payload", func(t *testing.T, ctl string, _ *anchortest.Stub) { plantSuccessAnchor(t, ctl) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctl, stub := anchoredViaStub(t)
			c.mutate(t, ctl, stub)
			gateCode, gateOut := verifyControl(t, "--control-log", ctl, "--offline")
			var out bytes.Buffer
			if code := cmdInvestigate([]string{"--log-dir", t.TempDir(), "--control-log", ctl, "--json"}, &out); code != 0 {
				t.Fatalf("investigate must exit 0: %d\n%s", code, out.String())
			}
			res, err := investigate.DecodeJSON(out.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			var events []investigate.Record
			for _, e := range res.Events {
				if e.Source == "control" && e.Kind == "anchor" && e.Outcome == "success" {
					events = append(events, e)
				}
			}
			lines := gateAnchorLines(gateOut)
			if len(lines) != len(events) || len(lines) == 0 {
				t.Fatalf("%d gate lines, %d investigate anchor events\n%s\n%s", len(lines), len(events), gateOut, out.String())
			}
			anyMismatch, anyUnverifiable := false, false
			for i, line := range lines {
				verdict, cause := gateVerdict(t, line)
				a := events[i].Anchor
				if a == nil || a.Verdict != verdict || a.Cause != cause {
					t.Fatalf("anchor %d: gate %q\ninvestigate %+v", i, line, a)
				}
				anyMismatch = anyMismatch || verdict == "mismatch"
				anyUnverifiable = anyUnverifiable || verdict == "unverifiable"
				if strings.HasPrefix(line, "anchor record seq ") {
					if b, _ := json.Marshal(a); string(b) != `{"verdict":"mismatch","cause":"anchor record without coverage"}` {
						t.Fatalf("planted record: %s", b)
					}
				}
			}
			switch {
			case anyMismatch && gateCode != exitAnchorMismatch, !anyMismatch && anyUnverifiable && gateCode != exitAnchorUnverifiable, !anyMismatch && !anyUnverifiable && gateCode != 0:
				t.Fatalf("gate exit %d with mismatch=%v unverifiable=%v\n%s", gateCode, anyMismatch, anyUnverifiable, gateOut)
			}
		})
	}
}
