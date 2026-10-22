package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/agenthof/agenthof/internal/broker"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/ledger"
	"github.com/agenthof/agenthof/internal/origin"
	"github.com/agenthof/agenthof/internal/sink"
)

// sinkSpec is what sinkBackendFor dispatches on: the posture's sink_backend
// coordinates and the bound on each call to the sink.
type sinkSpec struct {
	Backend config.IntegrityBackend
	Timeout time.Duration
}

// sinkHTTPClient is the one client every sink backend is built over:
// system roots, no custom CA knob; sink.NewS3 copies it and disables
// redirects on the copy.
var sinkHTTPClient = &http.Client{}

// sinkBackendFor is the dispatch from a sink backend kind to a Backend with
// the write path's concerns added — the shared HTTP client and the
// credential broker. s3-object-lock is the only kind this build constructs
// (Validate admits no other); every other kind is "not implemented". A
// build error is a posture this build cannot honour, judged before any
// network.
func sinkBackendFor(s sinkSpec) (sink.Backend, error) {
	switch s.Backend.Kind {
	case sink.KindS3ObjectLock:
		retention, err := config.ParseRetention(s.Backend.Retention)
		if err != nil {
			return nil, err
		}
		be, err := sink.NewS3(s.Backend.URL, sink.S3Options{Region: s.Backend.Region, Client: sinkHTTPClient, Keys: sinkKeys(s.Backend.Credential), Retention: retention, Timeout: s.Timeout})
		if err != nil {
			return nil, err
		}
		return be, nil
	default:
		return nil, fmt.Errorf("sink backend kind %q is not implemented", s.Backend.Kind)
	}
}

// newSink is sinkBackendFor behind a var so a test can hand in a stand-in
// (the newAnchorBackend pattern).
var newSink = sinkBackendFor

// sinkFor is the sink a posture names: nil — the floor, and never a typed
// nil — unless the posture is sink: worm, whose backend is built through
// the newSink seam.
func sinkFor(in config.Integrity, timeout time.Duration) (sink.Backend, error) {
	if in.Sink != "worm" {
		return nil, nil
	}
	return newSink(sinkSpec{Backend: in.SinkBackend, Timeout: timeout})
}

// sinkCredentialRef maps sink_backend.credential onto the broker's
// reference for the sink resource: a sigv4 key pair, every secret
// coordinate an env NAME.
func sinkCredentialRef(c config.BackendCredential) broker.CredentialRef {
	return broker.CredentialRef{
		ResourceID: "integrity/sink_backend",
		Source:     c.CredentialSource, ClientAuth: c.ClientAuth,
		ClientIDEnv: c.ClientIDEnv, ClientSecretEnv: c.ClientSecretEnv, TokenEnv: c.TokenEnv,
	}
}

// sinkKeys is the key-pair resolver the sink signs with: the broker reads
// the named variables per call, so the values live in the signature and
// nowhere else.
func sinkKeys(c config.BackendCredential) func(context.Context) (broker.KeyPair, error) {
	ref := sinkCredentialRef(c)
	return func(ctx context.Context) (broker.KeyPair, error) {
		return broker.StaticEnvKeyPair{}.ResolveKeyPair(ctx, ref)
	}
}

// protectedLine is the seal's line for the protected copy: the record's
// block and the sink's receipt — the version it confirmed and the lock as
// the sink reports it. A completion that found the copy already confirmed
// says so.
func protectedLine(res control.SealResult) string {
	line := fmt.Sprintf("protected: %s %s key=%s version=%s %s until %s", res.Sink.Kind, res.Sink.URL, res.Sink.Key, res.VersionID, res.Sink.Mode, res.RetainUntil.UTC().Format(time.RFC3339))
	if res.Existed {
		line += " (already confirmed)"
	}
	return line
}

// --- audit verify control: the sink pass ---

// copyState is the verdict on one protected copy. Three are definitive
// (exit 9); unverifiable is the absence of a verdict (exit 10).
type copyState int

const (
	copyVerified copyState = iota
	copyMissing
	copyMismatch
	copyUnderLocked
	copyUnverifiable
)

// copyVerdict is one protected copy judged: the verdict line (after its
// six-space indent), an information line beneath it when there is one
// (expiring, unlocked), and whether a delete marker sits on the key.
type copyVerdict struct {
	state        copyState
	verdict      string
	info         string
	deleteMarker bool
}

func unverifiableCopy(cause string) copyVerdict {
	return copyVerdict{state: copyUnverifiable, verdict: "unverifiable — " + cause}
}

// expiringWithin is the window before a copy's retention ends in which the
// verdict carries an expiring line: information, the exit unaffected.
const expiringWithin = 30 * 24 * time.Hour

// verifyCopy is the chain-first direction for one sealed segment that
// carries a sink block (record → sink), at now. The ladder, and which rung
// each verdict may come from — a definitive verdict needs a fact from a
// successful, parsed answer, never an error:
//
//  1. ListVersions(key) — exact key, non-marker versions oldest first. Any
//     error → unverifiable. Zero versions → MISSING (the one way to it).
//  2. The OLDEST version is the protected copy by construction (the seal
//     never writes on top): Get it whole, bounded by the larger of its
//     listed Size and the local segment's bytes (capped at
//     sink.MaxRestoreBody) — any error, the bound included → unverifiable;
//     a body whose length is not the listed Size → unverifiable (the
//     listing and the object disagree; a listing with no Size reads as 0);
//     a body of another length or another digest than the local segment →
//     LOCAL MISMATCH. The verdict is from complete, hash-compared bytes in
//     hand, never from a listing figure.
//  3. GetRetention on that version — any error → unverifiable (a 404
//     NoSuchObjectLockConfiguration is answered by the sink as "no lock":
//     mode and date both empty, not an error). A document that is not
//     whole — a date without a mode, a mode this verifier does not know —
//     is unverifiable, never a verdict. COMPLIANCE to at least the recorded
//     date → verified; otherwise UNDER-LOCKED, unless the recorded date has
//     passed, when the copy is verified and the lock's end is information.
//  4. Versions newer than a matching oldest are information: counted as
//     differing by Size or by digest; one that could not be read is counted
//     as unread, never as a verdict.
//
// A later version that matches the segment while the oldest does not is not
// the copy (the seal wrote the oldest) and does not change the verdict.
func verifyCopy(ctx context.Context, r control.SinkReader, seg control.Segment, now time.Time) copyVerdict {
	block := seg.Sink
	kv, err := r.ListVersions(ctx, block.Key)
	if err != nil {
		return unverifiableCopy(err.Error())
	}
	v := copyVerdict{deleteMarker: kv.DeleteMarker}
	if len(kv.Versions) == 0 {
		v.state, v.verdict = copyMissing, "MISSING — no version exists at the key (never written, or the lock is not what the posture claims)"
		return v
	}
	oldest := kv.Versions[0]
	id := origin.Clean(oldest.ID)
	mismatch := func() copyVerdict {
		v.state = copyMismatch
		v.verdict = fmt.Sprintf("LOCAL MISMATCH — the oldest version %s at the key does not hold the local segment's bytes: the local file was altered (the seal wrote the oldest; a later matching version is not the copy); run: agenthof audit restore control --segment %d", id, seg.N)
		return v
	}
	body, err := r.Get(ctx, block.Key, oldest.ID, min(max(oldest.Size, seg.Bytes), sink.MaxRestoreBody))
	if err != nil {
		return unverifiableCopy(err.Error())
	}
	if int64(len(body)) != oldest.Size {
		return unverifiableCopy(fmt.Sprintf("the listing and the object disagree on the size of version %s (%d listed, %d read)", id, oldest.Size, len(body)))
	}
	if int64(len(body)) != seg.Bytes || digest(body) != seg.SHA256 {
		return mismatch()
	}
	l, err := r.GetRetention(ctx, block.Key, oldest.ID)
	if err != nil {
		return unverifiableCopy(err.Error())
	}
	switch {
	case l.Mode == "" && !l.RetainUntil.IsZero():
		return unverifiableCopy(fmt.Sprintf("the retention document for version %s carries a date but no mode", id))
	case l.Mode != "" && l.Mode != "COMPLIANCE" && l.Mode != "GOVERNANCE":
		return unverifiableCopy(fmt.Sprintf("the retention document for version %s names a mode this verifier does not know: %s", id, origin.Clean(l.Mode)))
	}
	recorded, until := block.RetainUntil.UTC(), l.RetainUntil.UTC()
	held := l.Mode == "COMPLIANCE" && !until.Before(recorded)
	if !held && recorded.After(now) {
		v.state = copyUnderLocked
		var cause string
		switch {
		case l.Mode == "":
			cause = "is unlocked"
		case l.Mode != "COMPLIANCE":
			cause = fmt.Sprintf("is %s until %s", origin.Clean(l.Mode), until.Format(time.RFC3339))
		default:
			cause = fmt.Sprintf("is locked only until %s, before the recorded %s", until.Format(time.RFC3339), recorded.Format(time.RFC3339))
		}
		v.verdict = fmt.Sprintf("UNDER-LOCKED — version %s holds the bytes but %s", id, cause)
		return v
	}

	differ, unread := 0, 0
	for _, nv := range kv.Versions[1:] {
		if nv.Size != seg.Bytes {
			differ++
			continue
		}
		b, err := r.Get(ctx, block.Key, nv.ID, seg.Bytes)
		switch {
		case err != nil:
			unread++
		case digest(b) != seg.SHA256:
			differ++
		}
	}
	lock := "compliance until " + until.Format(time.RFC3339)
	if !held {
		lock = "unlocked"
		if l.Mode != "" {
			lock = strings.ToLower(origin.Clean(l.Mode)) + " until " + until.Format(time.RFC3339)
		}
	}
	tail := "bytes match"
	if differ > 0 {
		tail += fmt.Sprintf("; %d later versions differ: written over, the protected copy stands", differ)
	}
	if unread > 0 {
		tail += fmt.Sprintf("; %d later versions could not be read", unread)
	}
	v.verdict = fmt.Sprintf("verified — oldest version %s %s (%s)", id, lock, tail)
	switch {
	case !held:
		v.info = "unlocked — verified; the retention period ended " + recorded.Format(time.RFC3339)
	case !until.After(now):
		v.info = "unlocked — verified; the retention period ended " + until.Format(time.RFC3339)
	case until.Sub(now) <= expiringWithin:
		days := int((until.Sub(now) + 24*time.Hour - 1) / (24 * time.Hour)) // rounded up
		v.info = fmt.Sprintf("expiring — verified; retention ends in %d days", days)
	}
	return v
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// sinkVerdicts counts audit verify control's sink pass. The first five are
// per protected copy and sum to copies; held and accounted are the
// bucket-first direction (objects the sink holds under this ledger's
// prefix, and those the local set accounts for); inFlight counts objects a
// seal landed while this verification ran (the view re-read under the
// ledger's lock accounts for them, or could not be re-read) — no verdict;
// unlisted is set when the listing could not be done, which is no verdict
// on it.
type sinkVerdicts struct {
	copies, verified, missing, mismatch, underLocked, unverifiable int
	held, accounted, inFlight                                      int
	unlisted                                                       bool
}

// definitive is exit 9: a copy missing, altered locally or under-locked, or
// an object the local set does not account for. An unverifiable copy is
// never here — its key counts as accounted for by its ordinal (see
// verifySink), so no error, timeout or refusal can reach this verdict — and
// neither is an object a fresh view explains.
func (s sinkVerdicts) definitive() bool {
	return s.missing+s.mismatch+s.underLocked > 0 || s.held > s.accounted
}

// undecided is exit 10: no verdict on at least one copy, on an object
// sealed during the verification, or on the listing.
func (s sinkVerdicts) undecided() bool { return s.unverifiable > 0 || s.inFlight > 0 || s.unlisted }

// segmentKeyRE is the one spelling of a segment's object name under the
// ledger's prefix.
var segmentKeyRE = regexp.MustCompile(`^seg-([0-9]{6})$`)

// Fixed lines of the sink pass.
const (
	sinkNotIndependent = " (sink address taken from the root being verified — not independent; pass --integrity)"
	sinkNoneLine       = "protected copies: none (if this root is meant to keep protected copies — integrity.yaml sink: worm — run audit seal)"
	sinkOfflineLine    = "protected copies: not checked (--offline)"
)

// verifySink is audit verify control's sink pass over a verified set: both
// directions of §10 and every line of the block, from the first protected
// copy line to the summary. It runs only on a root that has sealed (or
// whose rotation did not complete), or when --integrity names a posture
// explicitly — a never-sealed root on the box prints nothing and reads
// nothing, so its output is what it always was. --offline skips the pass:
// it is network by nature.
//
// The posture is the one new input: --integrity, else integrity.yaml beside
// the ledger, in which case the summary says the address is not
// independent. A posture that cannot be read, a sink this build cannot
// construct, or a local posture while records carry blocks makes every copy
// unverifiable and the listing undone — never exit 2 (a reader never exits
// 2 on root state) and never a definitive verdict.
//
// Chain-first (verifyCopy) judges each copy from its RECORD's address; a
// record naming a sink other than the posture's is unverifiable (the
// posture that names it is the one to pass). Bucket-first lists this
// ledger's prefix in the posture's sink: every object there must be the
// copy of a local segment that carries a block and whose oldest version
// chain-first did not find altered. The view v was read before the network
// phase and its lock released, so a seal that runs meanwhile lands an
// object past v's last segment: an ordinal v cannot account for is judged
// again against the view re-read ONCE under the ledger's shared lock (which
// waits out a seal in flight) — a segment it now lists, or its rotating
// segment, is in flight, no verdict; the rotating segment of an incomplete
// rotation is pending (exit 8's domain). Only an object the FRESH view still
// cannot account for is definitive: the local set lost or replaced what the
// sink still holds.
func verifySink(controlLog, integrityFlag string, v control.View, offline bool, timeout time.Duration, out io.Writer) sinkVerdicts {
	if offline {
		_, _ = fmt.Fprintln(out, sinkOfflineLine)
		return sinkVerdicts{}
	}
	blocks := 0
	for _, seg := range v.Sealed {
		if seg.Sink != nil {
			blocks++
		}
	}
	independent := integrityFlag != ""
	var in config.Integrity
	var fault error
	if independent {
		in, fault = loadIntegrityAt(integrityFlag)
	} else {
		in, fault = loadIntegrity(controlLog)
	}
	// be is the sink the posture names; nil with a cause when there is none
	// this pass can read.
	var be sink.Backend
	cause := ""
	switch {
	case fault != nil:
		cause = fault.Error()
	case in.Sink != "worm":
		if blocks == 0 {
			_, _ = fmt.Fprintln(out, sinkNoneLine)
			return sinkVerdicts{}
		}
		cause = "no sink credential configured"
	default:
		built, err := sinkFor(in, timeout)
		if err != nil {
			cause = err.Error()
		} else {
			be = built
		}
	}
	worm := fault == nil && in.Sink == "worm"

	ctx := context.Background()
	now := time.Now()
	var s sinkVerdicts
	altered := map[int]bool{} // ordinals whose oldest version chain-first found not to be the local segment
	for _, seg := range v.Sealed {
		if seg.Sink == nil {
			if worm {
				_, _ = fmt.Fprintln(out, "  protected copy: none (sealed before sink: worm)")
			}
			continue
		}
		s.copies++
		b := seg.Sink
		// Kind, URL and Key come from the ledger, which an attacker may have
		// written; origin.Clean strips control characters before any of them
		// reaches a terminal.
		_, _ = fmt.Fprintf(out, "  protected copy: %s %s key=%s\n", origin.Clean(b.Kind), origin.Clean(b.URL), origin.Clean(b.Key))
		var c copyVerdict
		switch {
		case be == nil:
			c = unverifiableCopy(cause)
		case b.Kind != be.Kind() || b.URL != be.URL():
			c = unverifiableCopy(fmt.Sprintf("the record names %s %s but the posture names %s; pass the posture that names it", origin.Clean(b.Kind), origin.Clean(b.URL), origin.Clean(be.URL())))
		default:
			c = verifyCopy(ctx, be, seg, now)
		}
		_, _ = fmt.Fprintf(out, "      %s\n", c.verdict)
		if c.deleteMarker {
			_, _ = fmt.Fprintln(out, "      key has a delete marker; the locked versions stand")
		}
		if c.info != "" {
			_, _ = fmt.Fprintf(out, "      %s\n", c.info)
		}
		switch c.state {
		case copyVerified:
			s.verified++
		case copyMissing:
			s.missing++
		case copyMismatch:
			s.mismatch++
			altered[seg.N] = true
		case copyUnderLocked:
			s.underLocked++
		default:
			s.unverifiable++
		}
	}

	// Bucket-first.
	if be == nil {
		s.unlisted = true
	} else {
		logID, err := v.LogID, error(nil)
		if logID == "" { // never sealed: the manifest does not name it, the genesis does
			logID, err = control.GenesisLogID(v.Records)
		}
		if err != nil {
			s.unlisted, cause = true, err.Error()
		} else {
			prefix := be.Prefix(logID)
			held, err := be.ListPrefix(ctx, prefix)
			if err != nil {
				s.unlisted, cause = true, err.Error()
			}
			// fresh re-reads the view once, under the ledger's shared lock,
			// the first time an ordinal past v's segments turns up.
			fresh := sync.OnceValues(func() (control.View, error) { return control.Read(controlLog, ledger.Locked) })
			for _, kv := range held {
				if len(kv.Versions) == 0 {
					continue // a delete marker alone holds nothing
				}
				key := origin.Clean(kv.Key)
				name, ok := strings.CutPrefix(kv.Key, prefix)
				if !ok {
					_, _ = fmt.Fprintf(out, "  sink: key %s is not under this ledger's prefix\n", key)
					continue
				}
				m := segmentKeyRE.FindStringSubmatch(name)
				if m == nil {
					_, _ = fmt.Fprintf(out, "  sink: key %s under this ledger's prefix is not a segment key\n", key)
					continue
				}
				n, _ := strconv.Atoi(m[1]) // six digits: never an error, never an overflow
				if n >= 1 && n <= len(v.Sealed) {
					s.held++
					if v.Sealed[n-1].Sink != nil && !altered[n] {
						s.accounted++
						continue
					}
					_, _ = fmt.Fprintf(out, "  sink: key %s is not accounted for by this ledger's local segments — segment %d missing or replaced locally; run: agenthof audit restore control --segment %d\n", key, n, n)
					continue
				}
				// Past v's segments: v may be stale. Judge against the fresh view.
				fv, err := fresh()
				switch {
				case err != nil:
					s.inFlight++
					_, _ = fmt.Fprintf(out, "  sink: key %s is segment %d, past this verification's view; the ledger could not be re-read: %v; re-run\n", key, n, err)
				case n >= 1 && n <= len(fv.Sealed):
					s.inFlight++
					_, _ = fmt.Fprintf(out, "  sink: key %s is segment %d, sealed during this verification; re-run\n", key, n)
				case fv.State == control.StateSealedNotRotated && n == fv.RotatingSegment():
					_, _ = fmt.Fprintf(out, "  sink: key %s is segment %d, whose rotation did not complete; run: agenthof audit seal\n", key, n)
				default:
					s.held++
					_, _ = fmt.Fprintf(out, "  sink: key %s is not accounted for by this ledger's local segments — segment %d missing or replaced locally; run: agenthof audit restore control --segment %d\n", key, n, n)
				}
			}
		}
	}

	summary := fmt.Sprintf("protected copies: %d (%d verified, %d missing, %d mismatch, %d under-locked, %d unverifiable); ", s.copies, s.verified, s.missing, s.mismatch, s.underLocked, s.unverifiable)
	if s.unlisted {
		summary += "sink not listed — " + cause
	} else {
		summary += fmt.Sprintf("sink holds %d objects for this ledger, %d accounted for", s.held, s.accounted)
		if s.inFlight > 0 {
			summary += fmt.Sprintf(", %d sealed during this verification — re-run", s.inFlight)
		}
	}
	if worm && !independent {
		summary += sinkNotIndependent
	}
	_, _ = fmt.Fprintln(out, summary)
	return s
}
