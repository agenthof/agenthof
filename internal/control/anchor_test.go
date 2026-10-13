package control_test

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/ledger"
)

// coveredHash is a 64-hex head hash for hand-built anchor records.
var coveredHash = strings.Repeat("ab", 32)

// recAnchor hand-builds an action "anchor" wire record (Append refuses to
// write one, so every reader test builds the on-disk shape by hand, as
// render_test.go's rec() does). anchor is the raw JSON object for the
// "anchor" key, placed after detail and before prev — the wire position the
// writer will use — or "" for a record without the key. hash is the
// config_hash, "" for none.
func recAnchor(seq int, outcome, hash, anchor string) ledger.Record {
	hashField, anchorField := "", ""
	if hash != "" {
		hashField = fmt.Sprintf(`"config_hash":%q,`, hash)
	}
	if anchor != "" {
		anchorField = `"anchor":` + anchor + `,`
	}
	raw := fmt.Sprintf(
		`{"v":"control/1","seq":%d,"time":"2026-10-13T10:%02d:00Z",`+
			`"action":"anchor","outcome":%q,`+
			`"invoker":{"subject":"dana@example.com","issuer":"local","method":"asserted"},`+
			`"witness":{"os_user":"dana","hostname":"host"},%s%s"prev":""}`,
		seq, seq, outcome, hashField, anchorField)
	return ledger.Record{Raw: []byte(raw)}
}

// TestDecodeAnchorPayload: the reserved payload decodes field for field —
// the full shape, the loosened locator/proof fields, a failed attempt that
// carries only what it tried to cover, and nil when the key is absent; a
// record written before the field existed decodes exactly as before.
func TestDecodeAnchorPayload(t *testing.T) {
	full := recAnchor(2, "success", "", `{"seq":1,"hash":"`+coveredHash+`","kind":"tlog","backend_kind":"transparency-log","backend":"https://log.example","ref":"12345","proof":"AQID"}`)
	d, err := control.Decode(full.Raw)
	if err != nil {
		t.Fatal(err)
	}
	want := &control.Anchor{Seq: 1, Hash: coveredHash, Kind: "tlog", BackendKind: "transparency-log", Backend: "https://log.example", Ref: "12345", Proof: "AQID"}
	if !reflect.DeepEqual(d.Anchor, want) {
		t.Fatalf("Anchor = %+v, want %+v", d.Anchor, want)
	}
	if d.Action != "anchor" || d.Outcome != "success" || d.Seq != 2 {
		t.Fatalf("%+v", d)
	}

	failed := recAnchor(3, "error", "", `{"seq":1,"hash":"`+coveredHash+`"}`)
	d, err = control.Decode(failed.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if d.Anchor == nil || d.Anchor.Seq != 1 || d.Anchor.Hash != coveredHash || d.Anchor.Ref != "" || d.Anchor.Proof != "" || d.Anchor.Kind != "" {
		t.Fatalf("a failed attempt carries only the covered head: %+v", d.Anchor)
	}

	none := recAnchor(4, "success", "", "")
	if d, err := control.Decode(none.Raw); err != nil || d.Anchor != nil {
		t.Fatalf("no key must decode nil: %+v %v", d.Anchor, err)
	}

	old := []byte(`{"v":"control/1","seq":1,"time":"2026-09-21T10:01:00Z","action":"apply","outcome":"success","invoker":{"subject":"dana@example.com","issuer":"local","method":"asserted"},"witness":{"os_user":"dana","hostname":"host"},"config_hash":"sha256:abc","prev":""}`)
	d, err = control.Decode(old)
	if err != nil || d.Anchor != nil || d.Action != "apply" || d.ConfigHash != "sha256:abc" {
		t.Fatalf("a pre-existing record must decode identically: %+v %v", d, err)
	}
}

// TestAppendRefusesAnchorRecords: never emitted, by construction. The
// refusal lands before ledger.Open — on a fresh root no file and no genesis
// appear — and before the reason rule, so an anchor is always refused as an
// anchor; a payload on any other action is refused the same way and leaves
// an existing ledger byte-identical.
func TestAppendRefusesAnchorRecords(t *testing.T) {
	const want = "control: anchor records are reserved; nothing anchors in this build"
	p := filepath.Join(t.TempDir(), "control.jsonl")
	inv := identity.Static("dana@example.com")
	w := control.CaptureWitness()
	for name, e := range map[string]control.Event{
		"anchor success with payload": {Action: "anchor", Outcome: "success", Invoker: inv, Witness: w, Anchor: &control.Anchor{Seq: 1, Hash: coveredHash, Kind: "tlog", Ref: "1"}},
		"anchor success no payload":   {Action: "anchor", Outcome: "success", Invoker: inv, Witness: w},
		"anchor error without reason": {Action: "anchor", Outcome: "error", Invoker: inv, Witness: w},
	} {
		if _, err := control.Append(p, e); err == nil || err.Error() != want {
			t.Fatalf("%s: err = %v, want %q", name, err, want)
		}
	}
	if _, err := os.Stat(p); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a refused anchor must create no file: stat err = %v", err)
	}

	if _, err := control.Append(p, control.Event{Action: "apply", Outcome: "success", Invoker: inv, Witness: w, ConfigHash: "sha256:abc"}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.Append(p, control.Event{Action: "apply", Outcome: "success", Invoker: inv, Witness: w, ConfigHash: "sha256:abc", Anchor: &control.Anchor{}}); err == nil || err.Error() != want {
		t.Fatalf("a payload on another action: err = %v, want %q", err, want)
	}
	after, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("a refused append must leave the ledger byte-identical")
	}
}

// TestAppendNeverWritesAnAnchorKey: every record the floor writers produce
// omits the key entirely — the wire shape of an existing ledger is unchanged.
func TestAppendNeverWritesAnAnchorKey(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	inv := identity.Static("dana@example.com")
	for _, e := range []control.Event{
		{Action: "apply", Outcome: "success", Invoker: inv, Witness: control.CaptureWitness(), ConfigHash: "sha256:abc", Bootstrap: true},
		{Action: "disable", Agent: "coder", Outcome: "success", Invoker: inv, Witness: control.CaptureWitness(), ConfigHash: "sha256:def"},
		{Action: "prune", Outcome: "success", Invoker: inv, Witness: control.CaptureWitness(), Detail: "pruned 0 run(s) and 0 artifact(s) older than 180d"},
	} {
		if _, err := control.Append(p, e); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		if strings.Contains(line, `"anchor"`) {
			t.Fatalf("no floor record may carry the key: %s", line)
		}
	}
}

// TestLastInstallingSkipsAnchorRecords: an anchor after an apply — with no
// hash, with the apply's hash, with a payload — never displaces the apply;
// the seven readers that take their install from LastInstalling are
// therefore unaffected by construction.
func TestLastInstallingSkipsAnchorRecords(t *testing.T) {
	apply := ledger.Record{Raw: []byte(`{"v":"control/1","seq":1,"time":"2026-10-13T10:01:00Z","action":"apply","outcome":"success","invoker":{"subject":"dana@example.com","issuer":"local","method":"asserted"},"witness":{"os_user":"dana","hostname":"host"},"config_hash":"sha256:aaa","prev":""}`)}
	for name, recs := range map[string][]ledger.Record{
		"no hash":      {apply, recAnchor(2, "success", "", `{"seq":1,"hash":"`+coveredHash+`","kind":"tlog","ref":"1"}`)},
		"with hash":    {apply, recAnchor(2, "success", "sha256:aaa", "")},
		"with payload": {apply, recAnchor(2, "success", "sha256:aaa", `{"seq":1,"hash":"`+coveredHash+`","kind":"tlog","ref":"1"}`)},
	} {
		last, ok := control.LastInstalling(recs)
		if !ok || last.Seq != 1 || last.Action != "apply" {
			t.Fatalf("%s: LastInstalling = ok=%v %+v, want the apply at seq 1", name, ok, last)
		}
	}
	if _, ok := control.LastInstalling([]ledger.Record{recAnchor(1, "success", "sha256:aaa", "")}); ok {
		t.Fatal("an anchor alone installs nothing")
	}
}
