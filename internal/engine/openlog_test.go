package engine

import (
	"errors"
	"regexp"
	"testing"
)

func TestOpenLogRefusesExistingRunID(t *testing.T) {
	dir := t.TempDir()
	id := NewRunID()
	l, err := OpenLog(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	// Even an EMPTY existing file is refused: the old Count()!=0 guard let
	// two writers both see an empty file and both write genesis.
	_, err = OpenLog(dir, id)
	if !errors.Is(err, ErrRunExists) {
		t.Fatalf("second OpenLog err = %v, want ErrRunExists", err)
	}
}

func TestNewRunIDIsEightBytes(t *testing.T) {
	for range 16 {
		id := NewRunID()
		if !regexp.MustCompile(`^r-[0-9a-f]{16}$`).MatchString(id) {
			t.Fatalf("NewRunID = %q, want r- + 16 hex", id)
		}
	}
}
