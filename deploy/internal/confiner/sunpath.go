package confiner

import "fmt"

// CheckSunPath refuses a unix-socket path that does not fit sockaddr_un.sun_path
// on goos, whose limit counts the terminating NUL: 104 bytes on darwin, 108
// elsewhere. A longer path is truncated or rejected by bind(2), so it is caught
// up front with a clear error.
func CheckSunPath(path, goos string) error {
	limit := 108
	if goos == "darwin" {
		limit = 104
	}
	if len(path) > limit-1 {
		return fmt.Errorf("unix socket path too long (%d bytes; the limit on %s is %d)", len(path), goos, limit)
	}
	return nil
}
