package control

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/agenthof/agenthof/internal/ledger"
)

// AnchorCheck is the structural verdict on one successful anchor record: does
// the chain, as it stands, still reproduce the head the record says was
// anchored? It is decided from the records alone — no network, no posture —
// so editing integrity.yaml, or deleting it, cannot silence an anchor the
// chain carries.
type AnchorCheck struct {
	RecordSeq int     // the anchor record's own seq
	Anchor    *Anchor // its payload as recorded; nil when the record carries none
	Mismatch  string  // "" when the chain reproduces the recorded head at the recorded seq; else the fixed cause
}

// CheckAnchors walks records in chain order and returns one AnchorCheck per
// record with action "anchor" and outcome "success". A failed or refused
// anchor tried or covered nothing and is skipped. For each success: the record
// must carry a payload; the recorded hash must be 64 lowercase hex; the
// covered seq must be before the record; and
// sha256(records[Seq-1].Raw) must equal the recorded hash. A record that does
// not decode is skipped, as every reader in this package skips it.
func CheckAnchors(records []ledger.Record) []AnchorCheck {
	var out []AnchorCheck
	for _, r := range records {
		var rec record
		if err := json.Unmarshal(r.Raw, &rec); err != nil || rec.Action != "anchor" || rec.Outcome != "success" {
			continue
		}
		c := AnchorCheck{RecordSeq: rec.Seq, Anchor: rec.Anchor}
		switch a := rec.Anchor; {
		case a == nil:
			c.Mismatch = "anchor record without coverage"
		case !anchorHashRE.MatchString(a.Hash):
			// Judged before the position: a planted record is refused on the
			// value it recorded, with a cause that embeds nothing from it, so
			// no reader prints an unvalidated hash and a record wrong on both
			// counts has one deterministic cause.
			c.Mismatch = "anchor hash is not a lowercase hex sha256"
		case a.Seq < 1 || a.Seq >= rec.Seq || a.Seq > len(records):
			c.Mismatch = fmt.Sprintf("anchor covers seq %d, which is not before the record (seq %d)", a.Seq, rec.Seq)
		default:
			sum := sha256.Sum256(records[a.Seq-1].Raw)
			if got := hex.EncodeToString(sum[:]); got != a.Hash {
				c.Mismatch = fmt.Sprintf("the chain does not reproduce the recorded head at seq %d (chain %s, recorded %s)", a.Seq, got, a.Hash)
			}
		}
		out = append(out, c)
	}
	return out
}
