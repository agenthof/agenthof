package main

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
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

func TestCountProcsFindsSelfOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("/proc is Linux-only; the compartment is Linux")
	}
	// The test binary's comm is "probe.test" (its basename).
	n, err := countProcs("probe.test")
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatalf("countProcs(probe.test) = %d, want at least this process", n)
	}
	n, err = countProcs("no-such-process-name")
	if err != nil || n != 0 {
		t.Fatalf("countProcs(no-such) = %d, %v; want 0, nil", n, err)
	}
}
