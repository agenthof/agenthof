package confiner

import (
	"strings"
	"testing"
)

func TestCheckSunPath(t *testing.T) {
	if CheckSunPath(strings.Repeat("a", 103), "darwin") != nil || CheckSunPath(strings.Repeat("a", 104), "darwin") == nil {
		t.Fatal("darwin: 103 fits, 104 does not (104 bytes including the NUL)")
	}
	if CheckSunPath(strings.Repeat("a", 107), "linux") != nil || CheckSunPath(strings.Repeat("a", 108), "linux") == nil {
		t.Fatal("linux: 108 including the NUL")
	}
	err := CheckSunPath(strings.Repeat("a", 104), "darwin")
	if err == nil || !strings.Contains(err.Error(), "unix socket path too long (104 bytes; the limit on darwin is 104)") {
		t.Fatalf("error text = %v", err)
	}
}
