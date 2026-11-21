package main

import (
	"regexp"
	"testing"
)

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-([0-9a-f])[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func uuidVersion(s string) string {
	m := uuidRe.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return m[1]
}

func uuidV5Shaped(s string) bool { return uuidVersion(s) == "5" }

func TestDeriveIDDeterministic(t *testing.T) {
	a, err := deriveID("meetings", "chunk-7")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := deriveID("meetings", "chunk-7")
	if a != b {
		t.Fatalf("same (collection,id) must derive the same UUID: %s != %s", a, b)
	}
	if !uuidV5Shaped(a) {
		t.Fatalf("not a canonical v5 UUID: %s", a)
	}
}

// A golden value pins the namespace and the algorithm: changing either
// silently re-keys every stored chunk.
func TestDeriveIDGolden(t *testing.T) {
	got, err := deriveID("meetings", "chunk-7")
	if err != nil {
		t.Fatal(err)
	}
	const want = "03d8a7bb-84ea-50e6-8012-300d582bd09d"
	if got != want {
		t.Fatalf("deriveID(meetings, chunk-7) = %s, want %s", got, want)
	}
}

func TestDeriveIDCollectionScoped(t *testing.T) {
	a, _ := deriveID("meetings", "chunk-7")
	b, _ := deriveID("notes", "chunk-7")
	if a == b {
		t.Fatal("same caller id in different collections must not collide")
	}
}

func TestDeriveIDNoConcatenationAmbiguity(t *testing.T) {
	a, _ := deriveID("ab", "c")
	b, _ := deriveID("a", "bc")
	if a == b {
		t.Fatal("(ab,c) and (a,bc) must not collide")
	}
}

func TestDeriveIDRandomWhenNoCaller(t *testing.T) {
	a, _ := deriveID("meetings", "")
	b, _ := deriveID("meetings", "")
	if a == b {
		t.Fatal("no caller id must produce a random v4 each time")
	}
	if uuidVersion(a) != "4" {
		t.Fatalf("not a canonical v4 UUID: %s", a)
	}
}
