package investigate

import (
	"encoding/json"
	"fmt"
)

// DecodeJSON parses an investigate/1 document (RenderJSON's output) back
// into a Result, so a client holding only the JSON can render it as text
// and derive the exit code exactly as the local command does. A document
// whose v is not "investigate/1" is rejected rather than half-read.
func DecodeJSON(data []byte) (Result, error) {
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return Result{}, fmt.Errorf("investigate: decode: %w", err)
	}
	if env.V != "investigate/1" {
		return Result{}, fmt.Errorf("investigate: unsupported document version %q", env.V)
	}
	r := Result{Events: env.Events, Sources: make([]Source, 0, len(env.Sources))}
	for _, s := range env.Sources {
		r.Sources = append(r.Sources, Source(s))
	}
	return r, nil
}
