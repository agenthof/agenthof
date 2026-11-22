package main

import (
	"reflect"
	"testing"
)

func TestParseSearch(t *testing.T) {
	cmds, err := parseScript("search last meeting")
	if err != nil {
		t.Fatal(err)
	}
	want := []command{{tool: "search", args: map[string]any{"query": "last meeting"}}}
	if !reflect.DeepEqual(cmds, want) {
		t.Fatalf("got %+v, want %+v", cmds, want)
	}
}

func TestParseRead(t *testing.T) {
	cmds, err := parseScript("read doc-123")
	if err != nil {
		t.Fatal(err)
	}
	want := []command{{tool: "readGoogleDoc", args: map[string]any{"documentId": "doc-123"}}}
	if !reflect.DeepEqual(cmds, want) {
		t.Fatalf("got %+v, want %+v", cmds, want)
	}
}

func TestParseCallWithKV(t *testing.T) {
	cmds, err := parseScript("call downloadFile fileId=x localPath=/tmp/y")
	if err != nil {
		t.Fatal(err)
	}
	want := []command{{tool: "downloadFile", args: map[string]any{"fileId": "x", "localPath": "/tmp/y"}}}
	if !reflect.DeepEqual(cmds, want) {
		t.Fatalf("got %+v, want %+v", cmds, want)
	}
}

func TestParseMultiple(t *testing.T) {
	cmds, err := parseScript("search a b; read d1")
	if err != nil {
		t.Fatal(err)
	}
	want := []command{
		{tool: "search", args: map[string]any{"query": "a b"}},
		{tool: "readGoogleDoc", args: map[string]any{"documentId": "d1"}},
	}
	if !reflect.DeepEqual(cmds, want) {
		t.Fatalf("got %+v, want %+v", cmds, want)
	}
}

func TestParseEmptyOrUnknown(t *testing.T) {
	for _, in := range []string{"", " ; ", "frobnicate x", "search", "read", "read a b", "call", "call t badpair", "call t =v"} {
		if _, err := parseScript(in); err == nil {
			t.Errorf("parseScript(%q) = nil error, want error", in)
		}
	}
}
