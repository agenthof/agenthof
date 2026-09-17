package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestDispatchUnknownSubcommand(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := dispatch([]string{"bogus"}, &out, &errBuf)
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if !strings.Contains(errBuf.String(), "Usage:") {
		t.Fatalf("stderr should carry usage, got: %q", errBuf.String())
	}
}

func TestDispatchNoArgs(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := dispatch(nil, &out, &errBuf); code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
}
