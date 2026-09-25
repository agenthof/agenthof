package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestDialTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := dialTCP(addr); err != nil {
		t.Fatalf("dial open listener: %v", err)
	}
	_ = ln.Close()
	if err := dialTCP(addr); err == nil {
		t.Fatal("dial of a closed port succeeded")
	}
}

func TestTouchCreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "marker")
	if err := touch(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}
