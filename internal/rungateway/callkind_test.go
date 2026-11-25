package rungateway

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"testing"
)

// Every model_call the door records carries the route's call kind, on every
// outcome: succeeded, refused (model, upstream status), failed, started.
func TestModelCallRecordsCallKind(t *testing.T) {
	t.Setenv("MODEL_KEY", "sk-provider")
	cases := []struct {
		name, route, kind, mode, body, wantStatus string
	}{
		{"chat succeeded", "v1/chat/completions", "chat", "", `{"model":"chat-model"}`, "succeeded"},
		{"chat refused model", "v1/chat/completions", "chat", "", `{"model":"other"}`, "refused"},
		{"chat refused upstream", "v1/chat/completions", "chat", "429", `{"model":"chat-model"}`, "refused"},
		{"chat started", "v1/chat/completions", "chat", "stream", `{"model":"chat-model"}`, "started"},
		{"chat failed", "v1/chat/completions", "chat", "huge", `{"model":"chat-model"}`, "failed"},
		{"embeddings succeeded", "v1/embeddings", "embeddings", "embed", `{"model":"embed-model","input":"x"}`, "succeeded"},
		{"embeddings refused model", "v1/embeddings", "embeddings", "embed", `{"model":"chat-model","input":"x"}`, "refused"},
		{"embeddings refused upstream", "v1/embeddings", "embeddings", "429", `{"model":"embed-model","input":"x"}`, "refused"},
		{"embeddings failed", "v1/embeddings", "embeddings", "stream", `{"model":"embed-model","input":"x"}`, "failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up := &modelUpstream{mode: tc.mode}
			_, base, token, events := embedGateway(t, up, embedAgent("chat-model", "embed-model"))
			resp := postDoor(t, base, token, tc.route, tc.body, http.Header{})
			_ = readBody(t, resp)
			if len(*events) != 1 {
				t.Fatalf("events = %+v", *events)
			}
			ev := (*events)[0]
			if ev.Type != "model_call" || ev.Status != tc.wantStatus {
				t.Fatalf("event = %+v, want a %s model_call", ev, tc.wantStatus)
			}
			if ev.CallKind != tc.kind {
				t.Fatalf("call_kind = %q, want %q", ev.CallKind, tc.kind)
			}
		})
	}
}

func TestModelCallEmbeddingsUnsetStampsKind(t *testing.T) {
	t.Setenv("MODEL_KEY", "sk-provider")
	_, base, token, events := embedGateway(t, &modelUpstream{mode: "embed"}, embedAgent("chat-model", ""))
	_ = readBody(t, postEmbed(t, base, token, `{"input":"x"}`, nil))
	if len(*events) != 1 || (*events)[0].CallKind != "embeddings" {
		t.Fatalf("events = %+v", *events)
	}
}

// Source pin: modelDoor records only through the wrapper that stamps the call
// kind. The raw appender is referenced exactly twice (its parameter and the
// wrapper), so a future append site cannot bypass the stamp.
func TestModelDoorAppendsOnlyThroughKindStamp(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "proxy.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "modelDoor" {
			continue
		}
		found = true
		n := 0
		ast.Inspect(fn, func(nd ast.Node) bool {
			if id, ok := nd.(*ast.Ident); ok && id.Name == "rawAppend" {
				n++
			}
			return true
		})
		if n != 2 {
			t.Fatalf("rawAppend referenced %d times in modelDoor, want 2 (parameter + the stamping wrapper)", n)
		}
	}
	if !found {
		t.Fatal("modelDoor not found")
	}
}
