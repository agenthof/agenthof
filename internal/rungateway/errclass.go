package rungateway

import (
	"context"
	"errors"
	"net"
	"syscall"
)

// errClass reduces a transport-leg error to a stable class for a log line.
// The error's text is never logged: a wrapped *url.Error carries the full
// upstream URL (query string included) and a broker error can carry
// whatever the token endpoint answered, so only this class and a fixed
// message reach the operational log. Order matters: the context sentinels
// and ECONNREFUSED are checked by identity first, then DNS, then any
// net.Error reporting a timeout.
func errClass(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection_refused"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "dns"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	return "other"
}
