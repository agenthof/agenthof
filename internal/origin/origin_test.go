package origin

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSanitized(t *testing.T) {
	long := strings.Repeat("é", 300)
	o := &Origin{Via: "api", UserAgent: "evil\x1b[2J\r\n\x00" + long, ForwardedFor: "1.2.3.4\n5.6.7.8"}
	got := o.Sanitized()
	if strings.ContainsAny(got.UserAgent, "\x1b\r\n\x00") {
		t.Fatalf("non-printables must be stripped: %q", got.UserAgent)
	}
	if n := utf8.RuneCountInString(got.UserAgent); n != fieldMax {
		t.Fatalf("UserAgent runes = %d, want the cap %d", n, fieldMax)
	}
	if got.ForwardedFor != "1.2.3.45.6.7.8" {
		t.Fatalf("ForwardedFor = %q", got.ForwardedFor)
	}
	if o.UserAgent == got.UserAgent {
		t.Fatal("Sanitized must return a copy, not mutate the caller's value")
	}
	if (*Origin)(nil).Sanitized() != nil {
		t.Fatal("nil must stay nil")
	}
}

func TestClean(t *testing.T) {
	if got := Clean("roles/x.yaml: \x1b[31mred\x1b[0m\n"); got != "roles/x.yaml: [31mred[0m" {
		t.Fatalf("Clean = %q", got)
	}
	if got := Clean(strings.Repeat("a", 250)); utf8.RuneCountInString(got) != fieldMax {
		t.Fatalf("Clean must cap at %d runes, got %d", fieldMax, utf8.RuneCountInString(got))
	}
	if got := Clean("plain"); got != "plain" {
		t.Fatalf("a printable short string is untouched: %q", got)
	}
	if got := Clean("bad\xffbyte"); got != "badbyte" {
		t.Fatalf("invalid UTF-8 is dropped: %q", got)
	}
}
