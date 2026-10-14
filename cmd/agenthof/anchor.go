package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/agenthof/agenthof/internal/anchor"
	"github.com/agenthof/agenthof/internal/anchorverify"
	"github.com/agenthof/agenthof/internal/authz"
	"github.com/agenthof/agenthof/internal/broker"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/ledger"
	"github.com/agenthof/agenthof/internal/origin"
)

// audit verify control's two anchor exit codes, beside exitInstalledMismatch
// (installed.go) in the fixed precedence 1, 6, 3, 4, 5, 7: 6 is a definitive
// content disagreement — the chain does not reproduce a recorded head, or the
// stored proof under the trusted key says otherwise; 7 is the absence of a
// verdict — a log that could not be reached, a key the verifier does not
// hold. 7 never reads as tamper detected, and every definitive verdict
// outranks it.
const (
	exitAnchorMismatch     = 6
	exitAnchorUnverifiable = 7
)

// anchorPubPath is the transparency log's pinned checkpoint key, BESIDE the
// control ledger exactly as verify.pub is — a different file from verify.pub
// on purpose: verify.pub is the operator's Ed25519 signing key this point
// trusts; anchor.pub is the LOG's ECDSA key. Operator-written; Agenthof never
// writes it. Derived here and nowhere else.
func anchorPubPath(controlLog string) string {
	return filepath.Join(filepath.Dir(controlLog), "anchor.pub")
}

// anchorKeyPath decides whether anchor verification is pinned and where the
// key is — pinnedKeyPath's twin. With --anchor-key given, the flag IS the
// pin: the path is returned as pinned whether or not it exists (absent or
// unreadable fails closed at loadAnchorPub, never unpinned). Without it,
// anchor.pub is stat'ed: absent ⇒ unpinned ("as served by the log"); any
// stat error other than not-exist is a fault the caller reports.
func anchorKeyPath(controlLog, anchorKey string) (pinned bool, path string, err error) {
	if anchorKey != "" {
		return true, anchorKey, nil
	}
	path = anchorPubPath(controlLog)
	exists, err := fileExists(path)
	if err != nil {
		return false, path, fmt.Errorf("pinned log key %s: %w", path, err)
	}
	return exists, path, nil
}

// loadAnchorPub reads and parses the pinned log key at path with
// anchor.ParseLogKey (ECDSA P-256 only); every error names the file, so a
// refusal reads "pinned log key <path>: <cause>".
func loadAnchorPub(path string) (*ecdsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("pinned log key %s: %w", path, err)
	}
	pub, err := anchor.ParseLogKey(data)
	if err != nil {
		return nil, fmt.Errorf("pinned log key %s: %w", path, err)
	}
	return pub, nil
}

// pinnedLogKey is the pin both anchor commands resolve: nil, nil when unpinned.
func pinnedLogKey(controlLog, anchorKey string) (*ecdsa.PublicKey, error) {
	pinned, path, err := anchorKeyPath(controlLog, anchorKey)
	if err != nil || !pinned {
		return nil, err
	}
	return loadAnchorPub(path)
}

// anchorCredentialRef maps anchor_backend.credential — the BackendCredential
// shape ToolResource already spells — onto the broker's reference: the first
// consumer of that mapping. Every secret coordinate is an env NAME.
func anchorCredentialRef(c config.BackendCredential) broker.CredentialRef {
	return broker.CredentialRef{
		ResourceID: "integrity/anchor_backend",
		Source:     c.CredentialSource, Grant: c.GrantType, ClientAuth: c.ClientAuth,
		Issuer: c.Issuer, TokenURL: c.TokenEndpoint, Scope: c.Scope, Audience: c.Audience,
		TokenEnv: c.TokenEnv, ClientIDEnv: c.ClientIDEnv, ClientSecretEnv: c.ClientSecretEnv,
	}
}

// anchorBearer is the bearer resolver audit anchor hands the backend: nil for
// no credential (the public good is anonymous); otherwise the broker resolves
// the direct-bearer or client_credentials grant at call time and the value
// goes into the Authorization header and nowhere else. token_exchange needs a
// subject token no CLI has; Validate refuses it, and this guard keeps a nil
// broker from ever being dereferenced if a ref reaches here another way.
func anchorBearer(c config.BackendCredential, client *http.Client) func(context.Context) (string, error) {
	if c == (config.BackendCredential{}) {
		return nil
	}
	ref := anchorCredentialRef(c)
	if ref.Grant == "token_exchange" {
		return func(context.Context) (string, error) {
			return "", errors.New("broker: token_exchange is not supported for an anchor backend")
		}
	}
	d := broker.Dispatch{StaticEnv: broker.StaticEnv{}, ClientCredentials: broker.NewClientCredentials(client)}
	return func(ctx context.Context) (string, error) { return d.Resolve(ctx, ref) }
}

// backendSpec is what anchorBackendFor dispatches on: on the write path the
// posture's kind, url and credential; on the verify path the RECORD's own
// backend_kind and backend (never integrity.yaml), no credential, and the
// --offline flag. Key is the pinned log key, nil when unpinned.
type backendSpec struct {
	Kind, URL  string
	Key        *ecdsa.PublicKey
	Credential config.BackendCredential
	Offline    bool
}

// anchorHTTPClient is the one client every anchor backend is built over:
// system roots, no custom CA knob; anchor.NewRekor copies it and disables
// redirects on the copy.
var anchorHTTPClient = &http.Client{}

// anchorBackendFor is the dispatch from a backend kind to a Backend with the
// write path's concerns added — the shared HTTP client and the credential
// broker. transparency-log is the only kind this build constructs; every
// other kind is "not implemented", the same text anchorverify.Default returns
// (pinned equal by a test) — on the verify path the caller reports that as
// unverifiable, never as a mismatch.
func anchorBackendFor(s backendSpec) (anchor.Backend, error) {
	switch s.Kind {
	case "transparency-log":
		return anchor.NewRekor(s.URL, anchor.RekorOptions{Client: anchorHTTPClient, Key: s.Key, Bearer: anchorBearer(s.Credential, anchorHTTPClient), Offline: s.Offline})
	default:
		return nil, fmt.Errorf("anchor backend kind %q is not implemented", s.Kind)
	}
}

// newAnchorBackend is anchorBackendFor behind a var so a test can hand in the
// stub (the statControlLog pattern): the stub is never reachable through a
// real posture, since Validate refuses kind rfc3161.
var newAnchorBackend = anchorBackendFor

// verifyBackendFactory is the verify path's anchorverify.Factory over the
// newAnchorBackend seam: the RECORD's own kind and url, the pinned key, and
// offline — no credential. audit verify control, investigate and serve all
// build their verify-side backends through it, so the test stub reaches all
// three through the one var.
func verifyBackendFactory(kind, url string, key *ecdsa.PublicKey, offline bool) (anchor.Backend, error) {
	return newAnchorBackend(backendSpec{Kind: kind, URL: url, Key: key, Offline: offline})
}

// cmdAuditAnchor is `audit anchor`: pin the control ledger's current head
// into the transparency log the root's integrity.yaml names, and record on
// the chain which head was pinned, where the log's entry is, the log's proof
// and which log key signed for it. Order, pinned (runs prune's order with the
// anchor steps added — the posture is consumed, not just checked):
//
//  1. the invoker (--token without AGENTHOF_OIDC_ISSUER → exit 2, unrecorded);
//  2. the posture (a fault → exit 2; anchor none or no file → exit 1,
//     unrecorded, zero network; tlog → its coordinates), then anchor.pub
//     (present and unusable → exit 2);
//  3. ledger writable (busy or damaged → exit 1, unrecorded);
//  4. a refused token → recorded refused;
//  5. the authorization read under installed.lock SHARED — exactly prune's;
//     network happens only past this line, so a refused caller causes no
//     public entry;
//  6. the head (the control ledger is empty → exit 1, unrecorded);
//  7. Submit under --timeout; ANY failure → recorded anchor error with what
//     it tried to cover, exit 1; the ledger is otherwise untouched;
//  8. Append the success record (a failure here → "anchored … but NOT
//     recorded", exit 1 — the public entry is harmless; the next tick records
//     a new one);
//  9. print the lines the cron ships off the box: the anchored: line is a
//     verifier input (audit verify control --expect-head seq:hash).
//
// No record ever carries a config_hash: an anchor installs nothing.
func cmdAuditAnchor(args []string, out io.Writer) int {
	fs := flag.NewFlagSet("audit anchor", flag.ContinueOnError)
	controlLog := fs.String("control-log", ".agenthof/control.jsonl", "control-plane ledger path; integrity.yaml and anchor.pub are read from beside it")
	as := fs.String("as", "", "invoker identity (defaults to the OS user); ignored when --token is given")
	groups := fs.String("groups", "", "comma-separated groups asserted for the --as identity; DEV ONLY — self-asserted, not verified, ignored when --token is given")
	token := fs.String("token", "", "raw OIDC token to authenticate the invoker (env AGENTHOF_TOKEN fallback); a production cron presents this, not --as/--groups")
	timeout := fs.Duration("timeout", 30*time.Second, "bound on the whole exchange with the log")
	fs.SetOutput(out)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	inv, assertedAs, refused, usageErr, verifyErr := resolveInvoker(*as, *groups, *token)
	if usageErr {
		_, _ = fmt.Fprintln(out, "audit anchor: AGENTHOF_OIDC_ISSUER must be set in the environment to authenticate --token")
		return 2
	}

	in, err := loadIntegrity(*controlLog)
	if err != nil {
		_, _ = fmt.Fprintf(out, "audit anchor: %v\n", err)
		return 2
	}
	if in.Anchor != "tlog" {
		_, _ = fmt.Fprintf(out, "audit anchor: no anchor configured in %s (anchor: none); set anchor: tlog and anchor_backend to anchor this ledger\n", integrityPath(*controlLog))
		return 1
	}
	pub, err := pinnedLogKey(*controlLog, "")
	if err != nil {
		_, _ = fmt.Fprintf(out, "audit anchor: %v\n", err)
		return 2
	}
	keyMode := "as served"
	if pub != nil {
		keyMode = "pinned"
	}
	if !controlLedgerWritable("audit anchor", *controlLog, out) {
		return 1
	}

	// shipped holds the anchored: lines; set before the success record so they
	// print only once the record has landed, and before the head line every
	// writer prints last.
	var shipped []string
	record := func(outcome string, reason *control.Reason, payload *control.Anchor, code int) int {
		head, appendErr := control.Append(*controlLog, control.Event{
			Action: "anchor", Outcome: outcome, Reason: reason,
			Invoker: inv, AssertedAs: assertedAs, Witness: control.CaptureWitness(),
			Anchor: payload,
		})
		if appendErr != nil {
			_, _ = fmt.Fprintln(out, appendErr)
			if outcome == "success" {
				_, _ = fmt.Fprintf(out, "audit anchor: anchored at %s but NOT recorded\n", payload.Ref)
			}
			return 1
		}
		for _, l := range shipped {
			_, _ = fmt.Fprintln(out, l)
		}
		_, _ = fmt.Fprintf(out, "control head: seq=%d sha256=%s\n", head.Count, head.Hash)
		return code
	}

	if refused {
		_, _ = fmt.Fprintf(out, "audit anchor: token authentication failed: %v\n", verifyErr)
		return record("refused", &control.Reason{Code: control.CodeTokenVerificationFailed, Message: "token verification failed"}, nil, 1)
	}
	// The one read of the installed configuration — pointer, roles and the
	// ledger's vouch — under installed.lock SHARED, released before anything
	// is recorded or sent. Lock order store → ledger, as every reader.
	store := installedStore(*controlLog)
	unlock, lockErr := ledger.LockFileShared(installedLock(*controlLog))
	if lockErr != nil {
		if errors.Is(lockErr, ledger.ErrLockHeld) {
			_, _ = fmt.Fprintf(out, "audit anchor: %s\n", msgLockBusy)
			return 1
		}
		_, _ = fmt.Fprintln(out, lockErr)
		return record("error", &control.Reason{Code: control.CodeIOError, Message: truncateErr(lockErr)}, nil, 1)
	}
	installedRoles, _, installed, refusal, instErr := func() (roles []config.RoleDef, hash string, installed bool, refusal *verifyRefusal, err error) {
		defer unlock()
		roles, hash, installed, err = config.InstalledRoles(store)
		if err != nil || !installed {
			return roles, hash, installed, nil, err
		}
		_, _, refusal = vouchInstalled(*controlLog, hash)
		return roles, hash, installed, refusal, nil
	}()
	if instErr != nil {
		_, _ = fmt.Fprintln(out, instErr)
		_, _ = fmt.Fprint(out, installedHatch("audit anchor", "anchor", store))
		return record("error", &control.Reason{Code: control.CodeIOError, Message: truncateErr(instErr)}, nil, 1)
	}
	if !installed {
		_, _ = fmt.Fprintf(out, "audit anchor: %s\n", msgNothingInstalled)
		_, _ = fmt.Fprintf(out, "%s under %s; run: agenthof apply --config <dir> --control-log %s\n", msgNoConfigInstalled, store, *controlLog)
		return record("refused", &control.Reason{Code: control.CodeNotAuthorized, Message: msgNothingInstalled}, nil, 1)
	}
	if refusal != nil {
		switch {
		case refusal.Transient():
			_, _ = fmt.Fprintf(out, "audit anchor: %s\n", msgLockBusy)
			return 1
		case refusal.Kind != verifyNotOnRecord:
			_, _ = fmt.Fprintf(out, "audit anchor: %s\n", refusal.Error())
			return 1
		}
		_, _ = fmt.Fprintf(out, "audit anchor: %s\n", refusal.Error())
		return record("refused", vouchRefused(refusal), nil, 1)
	}
	if !authz.ControlAllows(installedRoles, inv, "anchor") {
		reason := control.NotAuthorized("anchor")
		_, _ = fmt.Fprintf(out, "audit anchor: %s\n", reason.Message)
		return record("refused", reason, nil, 1)
	}

	// The head. installed.lock is released; the record carries (seq, hash)
	// explicitly, so the head is free to advance under us.
	_, head, err := ledger.ReadVerify(*controlLog, ledger.Locked)
	if err != nil {
		_, _ = fmt.Fprintf(out, "audit anchor: %v\n", err)
		return 1
	}
	if head.Count == 0 {
		_, _ = fmt.Fprintln(out, "audit anchor: the control ledger is empty; nothing to anchor")
		return 1
	}
	covered := anchor.Head{Seq: head.Count, Hash: head.Hash}
	tried := &control.Anchor{Seq: covered.Seq, Hash: covered.Hash, Kind: "tlog", BackendKind: in.AnchorBackend.Kind, Backend: strings.TrimSuffix(in.AnchorBackend.URL, "/")}
	failed := func(err error) int {
		_, _ = fmt.Fprintf(out, "audit anchor: %v\n", err)
		return record("error", &control.Reason{Code: control.CodeAnchorFailed, Message: truncateErr(err)}, tried, 1)
	}

	// Network happens only from here.
	be, err := newAnchorBackend(backendSpec{Kind: in.AnchorBackend.Kind, URL: in.AnchorBackend.URL, Key: pub, Credential: in.AnchorBackend.Credential})
	if err != nil {
		return failed(err)
	}
	tried.BackendKind = be.Kind()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	rcpt, err := be.Submit(ctx, covered)
	cancel()
	if err != nil {
		return failed(err)
	}

	payload := &control.Anchor{Seq: covered.Seq, Hash: covered.Hash, Kind: "tlog", BackendKind: be.Kind(), Backend: rcpt.Backend, Ref: rcpt.Ref, Proof: rcpt.Proof, BackendKeyID: rcpt.BackendKeyID}
	keyID, index, integrated := rcpt.BackendKeyID, strconv.FormatInt(rcpt.LogIndex, 10), "-"
	if keyID == "" {
		keyID = "none"
	}
	if rcpt.LogIndex < 0 {
		index = "-"
	}
	if !rcpt.IntegratedTime.IsZero() {
		integrated = rcpt.IntegratedTime.UTC().Format(time.RFC3339)
	}
	// Record first: the printed lines are the artifact the cron ships, and a
	// head line for a record that did not land would be a lie. record prints
	// shipped, then the head — the spec's order.
	shipped = []string{
		fmt.Sprintf("anchored: seq=%d sha256=%s", covered.Seq, covered.Hash),
		fmt.Sprintf("  log: %s  entry: %s  log key: %s (%s)", rcpt.Backend, rcpt.Ref, keyID, keyMode),
		fmt.Sprintf("  index: %s  integrated: %s  (as reported by the log)", index, integrated),
	}
	return record("success", nil, payload, 0)
}

// expectHeadRE is --expect-head's grammar: the current head (<hex>) or the
// head the chain must reproduce at a position (<seq>:<hex>) — the latter is
// exactly the "anchored: seq=K sha256=H" line audit anchor prints, so a
// reference shipped off the box is a verifier input.
var expectHeadRE = regexp.MustCompile(`^([0-9]+:)?[0-9a-f]{64}$`)

// expectHeadMismatch judges --expect-head (already grammar-checked) against
// the verified chain and returns the line to print, or "" when it holds.
func expectHeadMismatch(expect string, records []ledger.Record, head ledger.Head) string {
	seqPart, hash, ok := strings.Cut(expect, ":")
	if !ok {
		if expect != head.Hash {
			return fmt.Sprintf("expect-head mismatch: want %s, got %s", expect, head.Hash)
		}
		return ""
	}
	n, err := strconv.Atoi(seqPart)
	if err != nil || n < 1 || n > len(records) {
		return fmt.Sprintf("expect-head mismatch: want %s at seq %s, but the chain has %d records", hash, seqPart, len(records))
	}
	sum := sha256.Sum256(records[n-1].Raw)
	if got := hex.EncodeToString(sum[:]); got != hash {
		return fmt.Sprintf("expect-head mismatch: want %s at seq %d, got %s", hash, n, got)
	}
	return ""
}

// anchorVerdicts counts audit verify control's three per-anchor outcomes.
type anchorVerdicts struct{ verified, mismatch, unverifiable int }

// verifyAnchors checks every successful anchor record the chain carries and
// prints one line per anchor plus a summary. Structural first
// (control.CheckAnchors — pure, posture-blind), then the backend built from
// the RECORD's own backend_kind and backend — never integrity.yaml — under the
// pinned log key (--anchor-key, else anchor.pub beside the ledger), or as
// served when neither is present. A key that cannot be loaded makes every
// anchor unverifiable, never exit 2: a reader never exits 2 on root state.
// The pin is resolved only when there is an anchor to verify. The ladder is
// anchorverify.Verify's; this function only prints.
func verifyAnchors(controlLog string, records []ledger.Record, anchorKey string, offline bool, timeout time.Duration, out io.Writer) anchorVerdicts {
	key := sync.OnceValues(func() (*ecdsa.PublicKey, error) { return pinnedLogKey(controlLog, anchorKey) })
	results := anchorverify.Verify(records, anchorverify.Options{ResolveKey: key, Factory: verifyBackendFactory, Offline: offline, Timeout: timeout})
	if len(results) == 0 {
		_, _ = fmt.Fprintln(out, "anchors: none (if this root is meant to be anchored — integrity.yaml anchor: tlog — run: agenthof audit anchor)")
		return anchorVerdicts{}
	}
	pub, _ := key() // memoized: resolved inside Verify, never a second read
	keyMode := "log key as served by the log — unpinned; pin it in anchor.pub or --anchor-key to verify independently"
	if pub != nil {
		keyMode = "log key pinned"
	}
	presence := ""
	if offline {
		presence = "; offline: presence not checked"
	}
	var v anchorVerdicts
	for _, r := range results {
		if r.Check.Anchor == nil {
			_, _ = fmt.Fprintf(out, "anchor record seq %d: MISMATCH — %s\n", r.Check.RecordSeq, r.Cause)
			v.mismatch++
			continue
		}
		a := r.Check.Anchor
		// a.Hash, a.Backend and a.Ref come from the ledger, which an attacker
		// may have written; origin.Clean strips control characters before any
		// of them reaches a terminal (an honest 64-hex hash is unchanged).
		// a.Seq is an int.
		where := fmt.Sprintf("anchor seq %d %s → %s entry %s", a.Seq, origin.Clean(a.Hash), origin.Clean(a.Backend), origin.Clean(a.Ref))
		switch r.State {
		case anchorverify.StateVerified:
			_, _ = fmt.Fprintf(out, "%s: verified (%s%s)\n", where, keyMode, presence)
			v.verified++
		case anchorverify.StateMismatch:
			_, _ = fmt.Fprintf(out, "%s: MISMATCH — %s\n", where, r.Cause)
			v.mismatch++
		default:
			_, _ = fmt.Fprintf(out, "%s: unverifiable — %s\n", where, r.Cause)
			v.unverifiable++
		}
	}
	_, _ = fmt.Fprintf(out, "anchors: %d (%d verified, %d mismatch, %d unverifiable)\n", len(results), v.verified, v.mismatch, v.unverifiable)
	return v
}
