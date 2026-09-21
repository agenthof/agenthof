package control

import (
	"encoding/json"
	"time"

	"github.com/agenthof/agenthof/internal/identity"
)

// DecodedEvent is the reader-facing companion to Event: it carries the
// full control/1 wire shape, including the writer-assigned Seq and Time
// that Event omits (callers never set those; readers need them to
// reconstruct chain order and timing). It deliberately excludes the
// chain-internal prev/log_id fields, which investigation code has no use
// for.
type DecodedEvent struct {
	V           string           `json:"v"`
	Seq         int              `json:"seq"`
	Time        time.Time        `json:"time"`
	Action      string           `json:"action"`
	Agent       string           `json:"agent,omitempty"`
	Outcome     string           `json:"outcome"`
	Reason      *Reason          `json:"reason,omitempty"`
	Invoker     identity.Invoker `json:"invoker"`
	AssertedAs  string           `json:"asserted_as,omitempty"`
	Witness     Witness          `json:"witness"`
	ConfigHash  string           `json:"config_hash,omitempty"`
	FragmentLen int              `json:"fragment_len,omitempty"`
	FragmentSHA string           `json:"fragment_sha256,omitempty"`
}

// Decode unmarshals a single control/1 log line into a DecodedEvent.
func Decode(raw []byte) (DecodedEvent, error) {
	var d DecodedEvent
	if err := json.Unmarshal(raw, &d); err != nil {
		return DecodedEvent{}, err
	}
	return d, nil
}
