package control

import (
	"errors"
	"fmt"
	"path/filepath"
)

// ErrSealed is the writer's verdict on an active segment that is sealed and
// not yet rotated (state B or C of a seal — the seal record is its last
// record, or the manifest lists it and the active name still refers to the
// sealed file). No writer appends to it; the remedy is to complete the
// rotation, never to repair.
var ErrSealed = errors.New("control: the active segment is sealed and not yet rotated; run: agenthof audit seal to complete the rotation")

// Fault classifies what Read found wrong with the segment set.
type Fault int

const (
	FaultTorn              Fault = iota // *ledger.TornError in segment Segment (0 = the active)
	FaultBroken                         // *ledger.ChainBrokenError mid-segment
	FaultBoundary                       // segment k's first record does not chain from segment k-1's head (k ≥ 2), or the active's from the last sealed head
	FaultMissingSegment                 // the manifest lists segment k; no such file
	FaultActiveMissing                  // a manifest or a .seg-* sibling exists; the active file does not (NOT fs.ErrNotExist)
	FaultUnexpectedSegment              // a .seg-* file the manifest does not list (and that is not the in-progress link), or .seg-* files with no manifest at all
	FaultManifest                       // the manifest cannot be parsed/validated, or disagrees with what the files verify to, or a seal payload does not recompute
	FaultSealNotLast                    // a successful seal record that is not its segment's last line
)

// SetError is the typed verdict on a segment set that does not verify.
// Segment is 0 for the active, else the sealed ordinal; Seq is the GLOBAL
// seq of the first record at fault (torn: the seq the torn tail would have
// had; broken/boundary/seal-not-last: the bad record; 0 when not
// applicable); Err is the underlying *ledger.TornError /
// *ledger.ChainBrokenError / parse or IO error. The unexported fields carry
// message detail only.
type SetError struct {
	Fault   Fault
	Segment int
	Path    string
	Seq     int
	Err     error

	want        string // an expected sha256, a sealed-segment count, the preceding segment's ordinal, or the segment's last seq, per Fault
	noManifest  bool   // FaultUnexpectedSegment: .seg-* files exist and no manifest does
	olderBinary bool   // FaultBoundary{0}: the active's first record is a fresh genesis (prev "", log_id set)
}

// Unwrap exposes Err ONLY when Fault ∈ {FaultTorn, FaultBroken} AND Segment
// == 0 — never by segment alone: errors.As(err, &torn) / errors.As(err,
// &broken) stay true exactly where audit repair control's torn/broken rules
// apply (the active file's own chain) and false for every sealed-segment or
// structural fault. FaultActiveMissing therefore never satisfies
// errors.Is(err, fs.ErrNotExist) (a root with history is not "nothing
// recorded") and FaultBoundary{0} never satisfies errors.As(&ChainBrokenError)
// (its remedy is not "run repair").
func (e *SetError) Unwrap() error {
	if (e.Fault == FaultTorn || e.Fault == FaultBroken) && e.Segment == 0 {
		return e.Err
	}
	return nil
}

func (e *SetError) Error() string {
	name := filepath.Base(e.Path)
	switch e.Fault {
	case FaultTorn, FaultBroken:
		if e.Segment == 0 {
			return e.Err.Error() // today's text for the active, byte for byte
		}
		what := "torn"
		if e.Fault == FaultBroken {
			what = "broken"
		}
		return fmt.Sprintf("control ledger segment %d (%s) %s at seq %d: a sealed segment is never repaired in place; restore it from a copy (expected sha256 %s) and run audit verify control", e.Segment, name, what, e.Seq, e.want)
	case FaultBoundary:
		if e.Segment == 0 {
			if e.olderBinary {
				return fmt.Sprintf("control ledger active segment does not chain from segment %s's head (seq %d): its first record is a fresh genesis (prev \"\", log_id set) — a writer older than this root's seals wrote it; upgrade every binary that shares the root, then move %s aside (its records are evidence, not chain) and create an empty %s in its place; the chain continues from seq %d", e.want, e.Seq-1, name, name, e.Seq-1)
			}
			return fmt.Sprintf("control ledger active segment does not chain from segment %s's head (seq %d): the active was replaced or rewritten, or a sealed segment was dropped and the manifest edited; restore from a copy and run audit verify control", e.want, e.Seq-1)
		}
		return fmt.Sprintf("control ledger boundary broken: segment %d (%s) does not chain from segment %d's head (seq %d): segment %d or %d was altered, replaced or reordered; restore from a copy and run audit verify control", e.Segment, name, e.Segment-1, e.Seq-1, e.Segment-1, e.Segment)
	case FaultMissingSegment:
		return fmt.Sprintf("control ledger segment %d missing: the manifest lists %s and it does not exist; restore it from a copy (expected sha256 %s)", e.Segment, name, e.want)
	case FaultActiveMissing:
		return fmt.Sprintf("control ledger active segment missing: %s lists %s sealed segments and %s does not exist; restore it from a copy, or remove the manifest and every segment to start a new ledger", filepath.Base(ManifestPath(e.Path)), e.want, name)
	case FaultUnexpectedSegment:
		if e.noManifest {
			return fmt.Sprintf("control ledger has segment files (%s …) but no manifest %s; restore the manifest from a copy, or rewrite it from audit verify control's segment lines", name, e.want)
		}
		return fmt.Sprintf("control ledger has an unexpected segment file %s the manifest does not list; move it aside and run audit verify control", name)
	case FaultManifest:
		if e.Segment == 0 {
			return fmt.Sprintf("control ledger manifest %s: %v; restore the manifest from a copy", name, e.Err)
		}
		return fmt.Sprintf("control ledger manifest disagrees with segment %d: %v; the chain is the record — rewrite the manifest entry from audit verify control's output, or restore the manifest from a copy", e.Segment, e.Err)
	case FaultSealNotLast:
		if e.Segment == 0 {
			return fmt.Sprintf("control ledger active segment has a seal record at seq %d that is not its last record (seq %s): records were appended after the seal, before its rotation completed — a writer older than this root's seals may have done it; upgrade every binary that shares the root, then run: agenthof audit repair control (it moves the records after the seal to a torn-fragment file and completes the rotation)", e.Seq-1, e.want)
		}
		return fmt.Sprintf("control ledger segment %d (%s) has a seal record at seq %d that is not its last record (seq %s): a sealed segment was appended to; a writer older than this root's seals may have done it — upgrade every binary that shares the root, then restore the segment from a copy", e.Segment, name, e.Seq-1, e.want)
	}
	return fmt.Sprintf("control ledger fault %d in segment %d: %v", e.Fault, e.Segment, e.Err)
}
