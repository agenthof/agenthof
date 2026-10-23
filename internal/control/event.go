// Package control implements the control/1 event type and a writer that
// appends control-plane events (apply, enable/disable, repair, ...) to a
// Locked, hash-chained ledger (internal/ledger). Every control record
// carries a contiguous "seq" from 1, distinguishing a control log from a
// run log (which never carries seq) per the ledger's seq-mode rule.
package control

import (
	"os"
	"os/user"

	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/origin"
)

// Reason codes for a control/1 record whose outcome is not "success".
const (
	CodeValidationFailed        = "validation_failed"
	CodeTokenVerificationFailed = "token_verification_failed"
	CodeLedgerDamaged           = "ledger_damaged"
	CodeAgentNotFound           = "agent_not_found"
	CodeIOError                 = "io_error"
	CodeNotAuthorized           = "not_authorized"
	// CodeNotOnRecord is the reason the control ledger does not vouch for the
	// installed pointer the action would be authorized against.
	CodeNotOnRecord = "not_on_record"
	// CodeAnchorFailed is the reason an anchor record carries when the
	// anchoring backend did not take, or did not prove, the head — a
	// transport failure, any non-201 from the log, a proof that did not
	// verify, a log key other than the pinned one, a credential the broker
	// could not resolve, a proof over the cap. Recorded, never fatal to the
	// ledger.
	CodeAnchorFailed = "anchor_failed"
)

// Reason explains a non-success outcome.
type Reason struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// NotAuthorized is the reason for a control action no role grants the
// invoker (authz.ControlAllows said no). The message is fixed and
// self-describing: it names the operation, never the invoker's groups.
func NotAuthorized(op string) *Reason {
	return &Reason{Code: CodeNotAuthorized, Message: "not authorized: no role grants " + op + " to the invoker"}
}

// Witness records the local OS user and hostname that produced a control
// record, independent of the asserted Invoker identity.
type Witness struct {
	OSUser   string `json:"os_user"`
	Hostname string `json:"hostname"`
}

// Event is a control/1 record. Callers set Action, Agent, Outcome, Reason,
// Invoker, AssertedAs, Witness, ConfigHash, Bootstrap (apply and
// enable/disable), Origin (an API-recorded action; nil from the CLI),
// Detail (runs prune and vouch), (anchor only) Anchor, and (repair only) FragmentLen/FragmentSHA. V, and the
// seq/time/prev/log_id fields on the wire, are set by Append; callers never
// set them.
type Event struct {
	V          string           `json:"v,omitempty"`
	Action     string           `json:"action"`
	Agent      string           `json:"agent,omitempty"`
	Outcome    string           `json:"outcome"`
	Reason     *Reason          `json:"reason,omitempty"`
	Invoker    identity.Invoker `json:"invoker"`
	AssertedAs string           `json:"asserted_as,omitempty"`
	Witness    Witness          `json:"witness"`
	ConfigHash string           `json:"config_hash,omitempty"`
	// Bootstrap marks a successful apply or kill-switch flip that ran while
	// nothing was installed under its control root. An apply so marked
	// installed the first snapshot (or the first after an operator removed
	// the installed pointer); a flip so marked edited the configuration
	// directory, recorded that directory's hash, and installed nothing — the
	// audit readers exclude it from "what is installed" (see Installing).
	// Additive: absent on every other record, omitted from the wire when
	// false.
	Bootstrap   bool   `json:"bootstrap,omitempty"`
	FragmentLen int    `json:"fragment_len,omitempty"`
	FragmentSHA string `json:"fragment_sha256,omitempty"`
	// Origin is where the action's request arrived from — set by serve on
	// an API-recorded action, nil from the CLI. Provenance from the
	// untrusted request channel, never a witness: the witness on an API
	// record is the serving host's OS user and hostname. Sanitized by
	// Append. Additive and omitempty (Article VI): absent on every record
	// written before it existed and on every CLI record after.
	Origin *origin.Origin `json:"origin,omitempty"`
	// Detail is a short human-readable summary of what a successful or
	// partially-successful action did, for the audit reader — "pruned 3 run(s)
	// and 1 artifact(s) older than 180d". It is forensic prose, not a join key:
	// nothing decides anything from it, and no reader parses it. Set by runs
	// prune and by vouch (what the ledger vouched for before); empty on every
	// other record. Sanitized by Append (origin.Clean:
	// printable runes only, at most 200). Additive and omitempty (Article VI):
	// absent on every record written before it existed and on every record
	// that does not set it.
	Detail string `json:"detail,omitempty"`
	// Anchor is the payload of an action "anchor" record, written by
	// "audit anchor": the head an external proof covers, and where that proof
	// is — never a secret (Article III bans secrets and artifact bodies from
	// an event, nothing else; a small proof is neither). Append admits it only
	// under a structural permit. An anchor is not an
	// install: it carries no config_hash and Installing never accepts it.
	// Additive and omitempty (Article VI).
	Anchor *Anchor `json:"anchor,omitempty"`
	// Seal is the payload of an action "seal" record: what the record says
	// about the segment it closes. Written by audit seal through the seam;
	// Append admits it only under a structural permit and a placement check
	// against the open chain. A seal installs nothing (no config_hash) and
	// Installing never accepts it. Additive and omitempty (Article VI).
	Seal *Seal `json:"seal,omitempty"`
}

// Seal is what a "seal" record says about the segment it closes. head_seq and
// head_hash equal this record's own seq-1 and prev; content_sha256 is
// sha256(file[0, offset of this line)) — every byte of the segment before the
// seal line, newlines included, never a whole-file hash (that is the
// manifest's sha256). Redundant by construction, cross-checked at write and
// recomputed at read; it identifies the unit, it adds no detection. Sink is
// the one field a reader cannot recompute: it is carried as recorded
// (sealChainFieldsAgree compares the five chain fields and ignores it).
type Seal struct {
	Segment       int    `json:"segment"`        // the ordinal this record closes (1-based; the manifest's n)
	FirstSeq      int    `json:"first_seq"`      // the segment's first seq (its Start.Base + 1)
	HeadSeq       int    `json:"head_seq"`       // the last record before this one: this record's seq - 1
	HeadHash      string `json:"head_hash"`      // its hash: this record's own prev
	ContentSHA256 string `json:"content_sha256"` // sha256 of the segment's bytes before this line
	// Sink is where the segment's protected copy goes and until when, on a
	// root whose posture is sink: worm; absent on a floor root, whose seal
	// line is byte-identical to one written before the block existed.
	// Additive and omitempty (Article VI).
	Sink *SealSink `json:"sink,omitempty"`
}

// Anchor is what an "anchor" record says about the head it pins, written by
// "audit anchor". One head per record: Hash is a single head hash; a
// batch over several heads would add a root field, never change Hash.
type Anchor struct {
	Seq  int    `json:"seq"`  // the covered head: seq of the last record the proof covers (1 ≤ Seq < this record's seq)
	Hash string `json:"hash"` // the covered head's hash: lowercase hex SHA-256 of record Seq's bytes (ledger.Head.Hash at Seq)
	Kind string `json:"kind"` // which knob produced it: "tlog" | "signed" (the integrity.yaml anchor value)
	// BackendKind is the proof FORMAT — the integrity backend kind vocabulary
	// ("transparency-log", "rfc3161", "kms", …) — so a verifier knows from
	// the record alone whether Ref is a log index or a content hash, without
	// reading integrity.yaml (which may have changed since).
	BackendKind string `json:"backend_kind,omitempty"`
	// Backend is the external service's public identity — the log origin,
	// the TSA endpoint, or a key URI — the proof is verifiable against.
	// A string on purpose: never to become an object. Never a secret.
	Backend string `json:"backend,omitempty"`
	// Ref is an opaque, backend-kind-defined LOCATOR for the entry: a
	// transparency-log entry id, or the sha256 of a proof kept beside the
	// ledger. Never a secret. Present on every successful anchor; absent on
	// a failed attempt, which has nothing to locate.
	Ref string `json:"ref,omitempty"`
	// Proof is a small, bounded proof that rides on the record itself, as
	// standard base64. For a transparency log it is the inclusion proof and
	// signed checkpoint, so the anchor verifies offline under a trusted key —
	// permanently, outliving the log's read API. For a TSA it is the RFC-3161
	// timestamp token (DER, 1–4 KB). Bounded (the first anchoring writer fixes
	// the cap and refuses above it); never a secret.
	Proof string `json:"proof,omitempty"`
	// BackendKeyID is the identity of the key the backend signed for this
	// entry with — lowercase hex SHA-256 of its PKIX DER (a transparency
	// log's log id). Forensic, not protective: it records which key the log
	// presented at anchor time so a later change is visible; the writer who
	// owns this file can rewrite it, and only a key pinned by the verifier
	// protects. Empty for a backend kind without a stable signing identity
	// (the test stub). Additive and omitempty.
	BackendKeyID string `json:"backend_key_id,omitempty"`
}

// CaptureWitness captures the local OS user (preferring $USER, falling
// back to os/user.Current) and hostname for a Witness.
func CaptureWitness() Witness {
	u := os.Getenv("USER")
	if u == "" {
		if cur, err := user.Current(); err == nil {
			u = cur.Username
		}
	}
	host, _ := os.Hostname()
	return Witness{OSUser: u, Hostname: host}
}
