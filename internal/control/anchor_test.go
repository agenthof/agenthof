package control_test

import (
	"bytes"
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

// goodAnchor is a complete success payload covering seq 1.
func goodAnchor() *control.Anchor {
	return &control.Anchor{Seq: 1, Hash: coveredHash, Kind: "tlog", BackendKind: "transparency-log", Backend: "https://rekor.sigstore.dev",
		Ref: strings.Repeat("0", 16) + strings.Repeat("ab", 32), Proof: "AQID", BackendKeyID: strings.Repeat("cd", 32)}
}

// appliedLedger returns a ledger with one apply record and the invoker/witness
// every test uses.
func appliedLedger(t *testing.T) (string, identity.Invoker, control.Witness) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "control.jsonl")
	inv, w := identity.Static("dana@example.com"), control.CaptureWitness()
	if _, err := control.Append(p, control.Event{Action: "apply", Outcome: "success", Invoker: inv, Witness: w, ConfigHash: "sha256:abc"}); err != nil {
		t.Fatal(err)
	}
	return p, inv, w
}

// TestAppendAcceptsAValidAnchor: a success anchor with a full payload, an
// error anchor with the covered head only, and a refused anchor with no
// payload each append; the payload round-trips field for field with
// backend_key_id last inside "anchor"; the record installs nothing.
func TestAppendAcceptsAValidAnchor(t *testing.T) {
	p, inv, w := appliedLedger(t)
	head, err := control.Append(p, control.Event{Action: "anchor", Outcome: "success", Invoker: inv, Witness: w, Anchor: goodAnchor()})
	if err != nil || head.Count != 2 {
		t.Fatalf("success: %v %+v", err, head)
	}
	if _, err := control.Append(p, control.Event{Action: "anchor", Outcome: "error", Reason: &control.Reason{Code: control.CodeAnchorFailed, Message: "status 501 from rekor.test"},
		Invoker: inv, Witness: w, Anchor: &control.Anchor{Seq: 2, Hash: coveredHash, Kind: "tlog", BackendKind: "transparency-log", Backend: "https://rekor.sigstore.dev"}}); err != nil {
		t.Fatalf("error: %v", err)
	}
	if _, err := control.Append(p, control.Event{Action: "anchor", Outcome: "refused", Reason: control.NotAuthorized("anchor"), Invoker: inv, Witness: w}); err != nil {
		t.Fatalf("refused: %v", err)
	}
	recs, _, err := ledger.ReadVerify(p, ledger.Locked)
	if err != nil || len(recs) != 4 {
		t.Fatalf("%v %d", err, len(recs))
	}
	d, err := control.Decode(recs[1].Raw)
	if err != nil || !reflect.DeepEqual(d.Anchor, goodAnchor()) {
		t.Fatalf("round trip: %+v %v", d.Anchor, err)
	}
	if want := `"anchor":{"seq":1,"hash":"` + coveredHash + `","kind":"tlog","backend_kind":"transparency-log","backend":"https://rekor.sigstore.dev","ref":"` + goodAnchor().Ref + `","proof":"AQID","backend_key_id":"` + strings.Repeat("cd", 32) + `"},"prev":"`; !strings.Contains(string(recs[1].Raw), want) {
		t.Fatalf("wire:\n%s\nwant %s", recs[1].Raw, want)
	}
	if strings.Contains(string(recs[3].Raw), `"anchor":`) {
		t.Fatalf("a refused anchor carries no payload: %s", recs[3].Raw)
	}
	if last, ok := control.LastInstalling(recs); !ok || last.Seq != 1 {
		t.Fatalf("an anchor never installs: %+v %v", last, ok)
	}
}

// TestAppendRefusesMalformedAnchors: each permit violation
// is refused with its exact text; every refusal appends nothing.
func TestAppendRefusesMalformedAnchors(t *testing.T) {
	p, inv, w := appliedLedger(t)
	before, _ := os.ReadFile(p)
	ok := control.Event{Action: "anchor", Outcome: "success", Invoker: inv, Witness: w}
	with := func(mut func(a *control.Anchor)) control.Event {
		e := ok
		a := goodAnchor()
		mut(a)
		e.Anchor = a
		return e
	}
	cases := map[string]struct {
		e    control.Event
		want string
	}{
		"payload on apply":        {control.Event{Action: "apply", Outcome: "success", Invoker: inv, Witness: w, ConfigHash: "sha256:abc", Anchor: &control.Anchor{}}, `control: anchor payload on a "apply" record`},
		"success without payload": {ok, "control: a successful anchor must say what it covers"},
		"refused with payload":    {control.Event{Action: "anchor", Outcome: "refused", Reason: control.NotAuthorized("anchor"), Invoker: inv, Witness: w, Anchor: goodAnchor()}, "control: a refused anchor tried nothing and covers nothing"},
		"config_hash":             {func() control.Event { e := with(func(*control.Anchor) {}); e.ConfigHash = "sha256:abc"; return e }(), "control: an anchor installs nothing and carries no config_hash"},
		"bad hex":                 {with(func(a *control.Anchor) { a.Hash = "ABCD" }), `control: anchor hash "ABCD" is not a lowercase hex sha256`},
		"proof over cap":          {with(func(a *control.Anchor) { a.Proof = strings.Repeat("A", control.MaxAnchorProofLen+1) }), "control: anchor proof is 8193 bytes; the cap is 8192"},
		"seq 0":                   {with(func(a *control.Anchor) { a.Seq = 0 }), "control: anchor covers seq 0 but the chain has 1 records"},
		"seq count+1":             {with(func(a *control.Anchor) { a.Seq = 2 }), "control: anchor covers seq 2 but the chain has 1 records"},
		"kind missing":            {with(func(a *control.Anchor) { a.Kind = "" }), "control: successful anchor record is incomplete (kind)"},
		"kind unknown":            {with(func(a *control.Anchor) { a.Kind = "tsa" }), `control: anchor kind "tsa" is not tlog or signed`},
		"backend_kind missing":    {with(func(a *control.Anchor) { a.BackendKind = "" }), "control: successful anchor record is incomplete (backend_kind)"},
		"backend missing":         {with(func(a *control.Anchor) { a.Backend = "" }), "control: successful anchor record is incomplete (backend)"},
		"ref missing":             {with(func(a *control.Anchor) { a.Ref = "" }), "control: successful anchor record is incomplete (ref)"},
		"proof missing":           {with(func(a *control.Anchor) { a.Proof = "" }), "control: successful anchor record is incomplete (proof)"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := control.Append(p, c.e); err == nil || err.Error() != c.want {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
			after, _ := os.ReadFile(p)
			if !bytes.Equal(before, after) {
				t.Fatal("a refused append must leave the ledger byte-identical")
			}
		})
	}
	// seq = Count is accepted (the head itself).
	if _, err := control.Append(p, with(func(a *control.Anchor) { a.Seq = 1 })); err != nil {
		t.Fatalf("seq == count: %v", err)
	}
}

// TestAppendAnchorRefusalLeavesTheLedgerUnchanged: on a FRESH root a pre-Open
// refusal (a malformed payload) leaves no file; a post-Open refusal (seq out
// of range on an empty chain) leaves an empty file and no record — "unchanged"
// is "no record appended", never "no file".
func TestAppendAnchorRefusalLeavesTheLedgerUnchanged(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	inv, w := identity.Static("dana@example.com"), control.CaptureWitness()
	bad := goodAnchor()
	bad.Hash = "nope"
	if _, err := control.Append(p, control.Event{Action: "anchor", Outcome: "success", Invoker: inv, Witness: w, Anchor: bad}); err == nil {
		t.Fatal("want refusal")
	}
	if _, err := os.Stat(p); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a pre-Open refusal must create no file: %v", err)
	}
	if _, err := control.Append(p, control.Event{Action: "anchor", Outcome: "success", Invoker: inv, Witness: w, Anchor: goodAnchor()}); err == nil || err.Error() != "control: anchor covers seq 1 but the chain has 0 records" {
		t.Fatalf("err = %v", err)
	}
	info, err := os.Stat(p)
	if err != nil || info.Size() != 0 {
		t.Fatalf("a post-Open refusal on a fresh root leaves an empty file: %v", err)
	}
	recs, head, err := ledger.ReadVerify(p, ledger.Locked)
	if err != nil || len(recs) != 0 || head.Count != 0 {
		t.Fatalf("no record may be appended: %v %d", err, len(recs))
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
