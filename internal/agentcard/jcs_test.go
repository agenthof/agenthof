package agentcard

import "testing"

func TestJCS(t *testing.T) {
	// Key order, number forms, string escapes and whitespace per RFC 8785.
	in := `{
	  "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001, -0, 100, 1e21, 1e-7],
	  "string": "\u20ac$\u000f\nA'\u0042\u0022\u005c\\\"\/",
	  "literals": [null, true, false],
	  "ba": 1, "b": 2, "\u00e9": 3, "A": 4
	}`
	want := `{"A":4,"b":2,"ba":1,"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27,0,100,1e+21,1e-7],"string":"€$\u000f\nA'B\"\\\\\"/","é":3}`
	got, err := jcsRaw([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestJCSKeyOrderUTF16(t *testing.T) {
	// U+1F600 encodes as surrogates D83D DE00, which sort before U+FF5E.
	got, err := jcsRaw([]byte("{\"～\":1,\"\U0001F600\":2}"))
	if err != nil {
		t.Fatal(err)
	}
	if want := "{\"\U0001F600\":2,\"～\":1}"; string(got) != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
