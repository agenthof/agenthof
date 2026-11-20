// Package agentcard parses an A2A agent card carrying an Agenthof extension
// and maps it to a proposed governed agent definition. It does not fetch
// cards; Verify checks a parsed card's signatures against trusted anchors.
package agentcard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/agenthof/agenthof/internal/config"
)

// ExtensionURI identifies the Agenthof extension in a card's
// capabilities.extensions list.
const ExtensionURI = "https://agenthof.dev/ext/agent/v1"

// MaxCardBytes caps the size of a card Parse will accept.
const MaxCardBytes = 256 << 10

// Card is the subset of an A2A agent card that enrollment needs.
type Card struct {
	Name         string       `json:"name"`
	Description  string       `json:"description"`
	Version      string       `json:"version"`
	Capabilities Capabilities `json:"capabilities"`
	Signatures   []Signature  `json:"signatures"`

	raw []byte
}

// Capabilities holds the card's declared extensions.
type Capabilities struct {
	Extensions []Extension `json:"extensions"`
}

// Extension is one declared A2A extension: an identifying URI and its params.
type Extension struct {
	URI    string          `json:"uri"`
	Params json.RawMessage `json:"params"`
}

// Signature is a card JWS signature, captured as-is and not verified here.
type Signature struct {
	Protected string          `json:"protected"`
	Signature string          `json:"signature"`
	Header    json.RawMessage `json:"header,omitempty"`
}

// AgenthofExt is the params of the Agenthof extension: what the agent is and
// what it asks to be granted. Requests are proposals, never grants.
type AgenthofExt struct {
	Artifact  string               `json:"artifact"`  // digest-pinned image reference
	Interface string               `json:"interface"` // how the agent is driven (informational)
	Tools     []config.ToolGrant   `json:"tools"`
	Exec      []string             `json:"exec"`
	Model     string               `json:"model"`
	Spawn     []config.SpawnTarget `json:"spawn"`
}

// Raw returns the exact bytes the card was parsed from.
func (c *Card) Raw() []byte { return c.raw }

// Parse decodes a card, rejecting oversized input, duplicate JSON keys, and
// trailing data. Signatures are captured, not verified.
func Parse(b []byte) (*Card, error) {
	if len(b) > MaxCardBytes {
		return nil, fmt.Errorf("agent card is %d bytes, over the %d byte limit", len(b), MaxCardBytes)
	}
	if err := rejectDuplicateKeys(b); err != nil {
		return nil, err
	}
	var c Card
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse agent card: %w", err)
	}
	c.raw = append([]byte(nil), b...)
	return &c, nil
}

// Extension returns the Agenthof extension; the card must carry exactly one.
func (c *Card) Extension() (AgenthofExt, error) {
	var found *Extension
	for i := range c.Capabilities.Extensions {
		if c.Capabilities.Extensions[i].URI != ExtensionURI {
			continue
		}
		if found != nil {
			return AgenthofExt{}, fmt.Errorf("agent card has more than one %s extension", ExtensionURI)
		}
		found = &c.Capabilities.Extensions[i]
	}
	if found == nil {
		return AgenthofExt{}, fmt.Errorf("agent card has no %s extension", ExtensionURI)
	}
	var ext AgenthofExt
	dec := json.NewDecoder(bytes.NewReader(found.Params))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ext); err != nil {
		return AgenthofExt{}, fmt.Errorf("parse agenthof extension params: %w", err)
	}
	if ext.Artifact == "" {
		return AgenthofExt{}, errors.New("agenthof extension has no artifact")
	}
	return ext, nil
}

// rejectDuplicateKeys walks the token stream and errors on a repeated key in
// any object (compared case-insensitively); encoding/json would silently
// keep the last one.
func rejectDuplicateKeys(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := scanValue(dec, 0); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("agent card has trailing data after the JSON value")
	}
	return nil
}

// maxDepth bounds JSON nesting so a hostile card cannot exhaust the stack.
const maxDepth = 64

func scanValue(dec *json.Decoder, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("agent card nests deeper than %d levels", maxDepth)
	}
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("parse agent card: %w", err)
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch d {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return fmt.Errorf("parse agent card: %w", err)
			}
			key, _ := kt.(string)
			// encoding/json folds keys by Unicode simple folding, which
			// strings.ToLower does not mirror (U+017F "ſ" matches "s"), so
			// a non-ASCII key could collide unseen. Every legitimate card
			// key is an ASCII identifier; refuse the rest.
			for i := 0; i < len(key); i++ {
				if key[i] >= 0x80 {
					return fmt.Errorf("agent card has non-ASCII key %q", key)
				}
			}
			// encoding/json matches struct fields case-insensitively, so
			// keys that differ only in case collide and must be refused.
			key = strings.ToLower(key)
			if seen[key] {
				return fmt.Errorf("agent card has duplicate key %q", key)
			}
			seen[key] = true
			if err := scanValue(dec, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := scanValue(dec, depth+1); err != nil {
				return err
			}
		}
	}
	if _, err := dec.Token(); err != nil { // closing delimiter
		return fmt.Errorf("parse agent card: %w", err)
	}
	return nil
}
