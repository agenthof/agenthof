package agentcard

import "testing"

const bs = "\x5c" // a backslash, so escapes below survive any tooling

func TestJCSRejects(t *testing.T) {
	for name, in := range map[string]string{
		"integer above 2^53":  `{"a":9007199254740993}`,
		"huge integer":        `{"a":123456789012345678901234567890}`,
		"overflow":            `{"a":1e400}`,
		"invalid UTF-8":       "{\"a\":\"\xff\"}",
		"lone high surrogate": `{"a":"` + bs + `ud800"}`,
		"lone low surrogate":  `{"a":"` + bs + `udc00"}`,
		"high then non-low":   `{"a":"` + bs + `ud800` + bs + `u0041"}`,
		"surrogate in key":    `{"` + bs + `ud800":1}`,
		"trailing data":       `{"a":1} {}`,
	} {
		if got, err := jcsRaw([]byte(in)); err == nil {
			t.Errorf("%s: accepted, got %s", name, got)
		}
	}
}

func TestJCSAccepts(t *testing.T) {
	for in, want := range map[string]string{
		`{"a":9007199254740992}`:                 `{"a":9007199254740992}`,
		`{"a":"` + bs + `ud83d` + bs + `ude00"}`: "{\"a\":\"\U0001F600\"}",
		`{"a":"` + bs + bs + `ud800"}`:           `{"a":"` + bs + bs + `ud800"}`,
		`{"a":1.5e3}`:                            `{"a":1500}`,
	} {
		got, err := jcsRaw([]byte(in))
		if err != nil || string(got) != want {
			t.Errorf("%s: got %s, %v; want %s", in, got, err, want)
		}
	}
}
