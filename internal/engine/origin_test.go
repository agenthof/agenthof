package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/agenthof/agenthof/internal/identity"
)

func TestOriginStampedOnStartAndRefusedOnly(t *testing.T) {
	dir := t.TempDir()
	o := &Origin{Via: "api", RemoteAddr: "127.0.0.1:50000", ForwardedFor: "10.0.0.9", UserAgent: "ua/1", ServerHost: "127.0.0.1:8080"}
	res, err := Run(context.Background(), engCfg(), "se", "fix-bug", "x",
		identity.Static("dev@x"), &fakeExec{fail: map[string]int{}},
		Options{LogDir: dir, ArtifactDir: filepath.Join(dir, "arts"), Origin: o})
	if err != nil || res.Status != "succeeded" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	events, _, err := ReadLog(dir, res.RunID)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		switch e.Type {
		case "workflow_started":
			if e.Origin == nil || *e.Origin != *o {
				t.Fatalf("workflow_started origin = %+v, want %+v", e.Origin, o)
			}
		default:
			if e.Origin != nil {
				t.Fatalf("%s carries origin %+v; only workflow_started and run_refused may", e.Type, e.Origin)
			}
		}
		if e.Binding.RunID == "" {
			t.Fatal("binding must still be stamped")
		}
	}

	res, _ = Run(context.Background(), engCfg(), "nobody", "fix-bug", "x",
		identity.Static("dev@x"), &fakeExec{fail: map[string]int{}},
		Options{LogDir: dir, ArtifactDir: filepath.Join(dir, "arts"), Origin: o})
	if res.Status != "refused" {
		t.Fatalf("res=%+v, want refused", res)
	}
	events, _, err = ReadLog(dir, res.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Type != "run_refused" || events[0].Origin == nil || *events[0].Origin != *o {
		t.Fatalf("run_refused must carry the origin: %+v", events)
	}
}

func TestOriginNilIsByteAbsent(t *testing.T) {
	data, err := json.Marshal(Event{Type: "workflow_started", ConfigHash: "abc"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("origin")) {
		t.Fatalf("a nil Origin must not serialize: %s", data)
	}
}

func TestOriginSanitized(t *testing.T) {
	long := strings.Repeat("é", 300)
	o := &Origin{Via: "api", UserAgent: "evil\x1b[2J\r\n\x00" + long, ForwardedFor: "1.2.3.4\n5.6.7.8"}
	got := o.sanitized()
	if strings.ContainsAny(got.UserAgent, "\x1b\r\n\x00") {
		t.Fatalf("non-printables must be stripped: %q", got.UserAgent)
	}
	if n := utf8.RuneCountInString(got.UserAgent); n != originFieldMax {
		t.Fatalf("UserAgent runes = %d, want the cap %d", n, originFieldMax)
	}
	if got.ForwardedFor != "1.2.3.45.6.7.8" {
		t.Fatalf("ForwardedFor = %q", got.ForwardedFor)
	}
	if o.UserAgent == got.UserAgent {
		t.Fatal("sanitized must return a copy, not mutate the caller's value")
	}
	if (*Origin)(nil).sanitized() != nil {
		t.Fatal("nil must stay nil")
	}
}

func TestOriginSanitizedThroughRun(t *testing.T) {
	dir := t.TempDir()
	o := &Origin{Via: "api", UserAgent: "x\x1b[31mred\x1b[0m"}
	res, err := Run(context.Background(), engCfg(), "se", "fix-bug", "x",
		identity.Static("dev@x"), &fakeExec{fail: map[string]int{}},
		Options{LogDir: dir, ArtifactDir: filepath.Join(dir, "arts"), Origin: o})
	if err != nil {
		t.Fatal(err)
	}
	events, _, _ := ReadLog(dir, res.RunID)
	if ua := events[0].Origin.UserAgent; ua != "x[31mred[0m" {
		t.Fatalf("ledgered UserAgent = %q, want the escapes stripped", ua)
	}
}
