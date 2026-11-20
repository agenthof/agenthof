// Package agentcard parses an A2A agent card carrying an Agenthof extension
// and maps it to a proposed governed agent definition. It does not fetch
// cards; Verify checks a parsed card's signatures against trusted anchors.
package agentcard

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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
	Artifact string `json:"artifact"` // digest-pinned image reference (the OCI image form)
	// HostProgram is the host-program artifact form: a program bound by
	// content hash, for tiers that run a host executable rather than an image.
	HostProgram *HostProgram         `json:"host-program,omitempty"`
	Interface   string               `json:"interface"` // how the agent is driven; enroll accepts only "a2a"
	Tools       []config.ToolGrant   `json:"tools"`
	Exec        []string             `json:"exec"`
	Model       string               `json:"model"`
	Spawn       []config.SpawnTarget `json:"spawn"`
}

// HostProgram names a host executable by a logical id (never a filesystem
// path) and lists the content hashes of its builds.
type HostProgram struct {
	Program string      `json:"program"`
	Builds  []HostBuild `json:"builds"`
}

// HostBuild is one build of a host program. OS and Arch label the hash for
// disclosure; they are not an enforcement key.
type HostBuild struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	SHA256 string `json:"sha256"` // "sha256:" + 64 lowercase hex
}

// Size caps on the host-program form, judged at parse so an oversized form is
// refused before the operator is asked to consent. They are at least as strict
// as the enroll record's caps (internal/control MaxEnrollProgramLen,
// MaxEnrollBuilds, MaxEnrollBuildFieldLen), and together they keep the
// disclosure line "host program <id> <os>/<arch> sha256:<64 hex>" (87 bytes
// besides the three fields) within the record's 256-byte per-entry cap:
// 128 + 20 + 20 + 87 = 255.
const (
	maxHostProgramLen = 128
	maxHostBuilds     = 32
	maxHostBuildField = 20
)

// validate checks the shape and size of the host-program form.
func (h *HostProgram) validate() error {
	if h.Program == "" {
		return errors.New("host-program has no program id")
	}
	if len(h.Program) > maxHostProgramLen {
		return fmt.Errorf("host-program id is over %d bytes", maxHostProgramLen)
	}
	if len(h.Builds) == 0 {
		return errors.New("host-program has no builds")
	}
	if len(h.Builds) > maxHostBuilds {
		return fmt.Errorf("host-program lists %d builds; the most allowed is %d", len(h.Builds), maxHostBuilds)
	}
	for i, b := range h.Builds {
		if b.OS == "" || b.Arch == "" {
			return fmt.Errorf("host-program build %d needs os and arch", i)
		}
		if len(b.OS) > maxHostBuildField || len(b.Arch) > maxHostBuildField {
			return fmt.Errorf("host-program build %d: os and arch are each limited to %d bytes", i, maxHostBuildField)
		}
		if !validSHA256(b.SHA256) {
			return fmt.Errorf("host-program build %d: sha256 must be sha256:<64 lowercase hex>", i)
		}
	}
	return nil
}

func validSHA256(s string) bool {
	hexPart, ok := strings.CutPrefix(s, "sha256:")
	if !ok || len(hexPart) != 64 {
		return false
	}
	for i := 0; i < len(hexPart); i++ {
		c := hexPart[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Raw returns a copy of the exact bytes the card was parsed from.
func (c *Card) Raw() []byte { return append([]byte(nil), c.raw...) }

// SignedDigest returns the hex SHA-256 of the JCS-canonical card body with
// "signatures" removed: the exact content a signature covers. Unlike a digest
// of Raw, it is the same for every encoding of one signed body. It returns ""
// if the card was not produced by Parse or cannot be canonicalized.
func (c *Card) SignedDigest() string {
	if c == nil || len(c.raw) == 0 {
		return ""
	}
	body, err := signedBody(c.raw)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// Parse decodes a card, rejecting oversized input, duplicate JSON keys, and
// trailing data. Signatures are captured, not verified.
func Parse(b []byte) (*Card, error) {
	if len(b) > MaxCardBytes {
		return nil, fmt.Errorf("agent card is %d bytes, over the %d byte limit", len(b), MaxCardBytes)
	}
	if err := rejectDuplicateKeys(b); err != nil {
		return nil, fmt.Errorf("agent card: %w", err)
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
	if ext.HostProgram != nil {
		if err := ext.HostProgram.validate(); err != nil {
			return AgenthofExt{}, fmt.Errorf("agenthof extension: %w", err)
		}
	}
	if ext.Artifact == "" && ext.HostProgram == nil {
		return AgenthofExt{}, errors.New("agenthof extension needs at least one artifact form (artifact or host-program)")
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
		return errors.New("trailing data after the JSON value")
	}
	return nil
}

// maxDepth bounds JSON nesting so a hostile card cannot exhaust the stack.
const maxDepth = 64

func scanValue(dec *json.Decoder, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("JSON nests deeper than %d levels", maxDepth)
	}
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("parse JSON: %w", err)
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
				return fmt.Errorf("parse JSON: %w", err)
			}
			key, _ := kt.(string)
			// encoding/json folds keys by Unicode simple folding, which
			// strings.ToLower does not mirror (U+017F "ſ" matches "s"), so
			// a non-ASCII key could collide unseen. Every legitimate card
			// key is an ASCII identifier; refuse the rest.
			for i := 0; i < len(key); i++ {
				if key[i] >= 0x80 {
					return fmt.Errorf("JSON has non-ASCII key %q", key)
				}
			}
			// encoding/json matches struct fields case-insensitively, so
			// keys that differ only in case collide and must be refused.
			key = strings.ToLower(key)
			if seen[key] {
				return fmt.Errorf("JSON has duplicate key %q", key)
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
		return fmt.Errorf("parse JSON: %w", err)
	}
	return nil
}
