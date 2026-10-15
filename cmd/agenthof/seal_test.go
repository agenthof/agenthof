package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/ledger"
)

// keyOrder returns a record's top-level keys in wire order.
func keyOrder(t *testing.T, raw []byte) []string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		t.Fatalf("not an object: %v", err)
	}
	var keys []string
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, tok.(string))
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			t.Fatal(err)
		}
	}
	return keys
}

// TestNoSealIsToday pins the hard invariant: a root that never seals is
// today's root. Drive apply → kill switch → anchor (stub) → prune; the root's
// directory holds exactly today's entries, every record's key sequence is
// the pre-change sequence for its action, no record carries "seal", log_id
// is on seq 1 only, and control.Read returns ledger.ReadVerify's records
// and head.
func TestNoSealIsToday(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	useStub(t)
	root := anchorSample(t)
	ctl := applied(t, root)
	tlogPostureFor(t, ctl, "http://stub.invalid")
	var out bytes.Buffer
	if code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("disable: %d\n%s", code, out.String())
	}
	out.Reset()
	if code := cmdAudit([]string{"anchor", "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("anchor: %d\n%s", code, out.String())
	}
	out.Reset()
	if code := cmdRuns([]string{"prune", "--older-than", "180d", "--log-dir", t.TempDir(), "--artifact-dir", t.TempDir(), "--control-log", ctl, "--as", "dana@example.com", "--groups", "platform-eng"}, &out); code != 0 {
		t.Fatalf("prune: %d\n%s", code, out.String())
	}
	entries, err := os.ReadDir(filepath.Dir(ctl))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if want := []string{"control.jsonl", "installed", "installed.lock", "integrity.yaml"}; strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("directory listing %v, want %v (no .segments, no .seg-*)", names, want)
	}
	want, wantHead, err := ledger.ReadVerify(ctl, ledger.Locked)
	if err != nil {
		t.Fatal(err)
	}
	v, err := control.Read(ctl, ledger.Locked)
	if err != nil || v.Head != wantHead || len(v.Records) != len(want) || v.Sealed != nil {
		t.Fatalf("Read ≠ ReadVerify: %v %+v", err, v.Head)
	}
	orders := map[string][]string{
		"apply":   {"v", "seq", "time", "action", "outcome", "invoker", "witness", "config_hash", "bootstrap", "prev", "log_id"},
		"disable": {"v", "seq", "time", "action", "agent", "outcome", "invoker", "witness", "config_hash", "prev"},
		"anchor":  {"v", "seq", "time", "action", "outcome", "invoker", "witness", "anchor", "prev"},
		"prune":   {"v", "seq", "time", "action", "outcome", "invoker", "witness", "detail", "prev"},
	}
	for i, r := range v.Records {
		if string(r.Raw) != string(want[i].Raw) {
			t.Fatalf("record %d differs", i)
		}
		if bytes.Contains(r.Raw, []byte(`"seal"`)) {
			t.Fatalf("record %d carries a seal key:\n%s", i, r.Raw)
		}
		var rec struct {
			Action string `json:"action"`
			LogID  string `json:"log_id"`
		}
		_ = json.Unmarshal(r.Raw, &rec)
		if (i == 0) != (rec.LogID != "") {
			t.Fatalf("log_id must be on seq 1 only (record %d: %q)", i+1, rec.LogID)
		}
		got := strings.Join(keyOrder(t, r.Raw), ",")
		if exp := strings.Join(orders[rec.Action], ","); got != exp {
			t.Fatalf("%s record key order:\n got %s\nwant %s", rec.Action, got, exp)
		}
	}
	if !regexp.MustCompile(`"seq":1,`).Match(v.Records[0].Raw) {
		t.Fatal("genesis is seq 1")
	}
}
