package rungateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestErrClass(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, "none"},
		{"deadline", context.DeadlineExceeded, "timeout"},
		{"wrapped deadline", fmt.Errorf("connect: %w", context.DeadlineExceeded), "timeout"},
		{"canceled", context.Canceled, "canceled"},
		{"refused via OpError", &net.OpError{Op: "dial", Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}}, "connection_refused"},
		{"refused via url.Error carrying a secret", &url.Error{Op: "Post", URL: "http://127.0.0.1:1/?key=SECRETVALUE", Err: syscall.ECONNREFUSED}, "connection_refused"},
		{"dns", &net.DNSError{Err: "no such host", Name: "x.invalid"}, "dns"},
		{"net timeout", &net.OpError{Op: "read", Err: &timeoutErr{}}, "timeout"},
		{"plain", errors.New("boom"), "other"},
	}
	for _, c := range cases {
		got := errClass(c.err)
		if got != c.want {
			t.Errorf("%s: errClass = %q, want %q", c.name, got, c.want)
		}
		if strings.Contains(got, "SECRET") || strings.Contains(got, "127.0.0.1") {
			t.Errorf("%s: class %q must never carry error text", c.name, got)
		}
	}
}

// timeoutErr is a net.Error whose Timeout() is true.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return false }

func TestErrClassLiveConnectionRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	_, err = net.Dial("tcp", addr)
	if err == nil {
		t.Fatal("dial to a closed port must fail")
	}
	if got := errClass(err); got != "connection_refused" {
		t.Fatalf("errClass(%v) = %q, want connection_refused", err, got)
	}
}
