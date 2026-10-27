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
	"log/slog"
	"net/http"
	"net/url"
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
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/investigate"
	"github.com/agenthof/agenthof/internal/ledger"
	"github.com/agenthof/agenthof/internal/obs"
	"github.com/agenthof/agenthof/internal/origin"
	"github.com/agenthof/agenthof/internal/sidecar"
)

// audit verify control's exit codes beside exitInstalledMismatch (installed.go),
// in the fixed precedence 1, 6, 9, 3, 4, 5, 7, 10, 8. 6 and 7 are the anchor
// verdicts: 6 is a definitive content disagreement — the chain does not
// reproduce a recorded head, or the stored proof under the trusted key says
// otherwise; 7 is the absence of a verdict — a log that could not be reached,
// a key the verifier does not hold. 9 and 10 are the sink verdicts on the
// same doctrine: 9 is definitive — a protected copy is missing, the oldest
// version at its key does not hold the local segment, a copy is locked less
// than the seal recorded, or the sink holds an object for this ledger that
// no local segment accounts for; 10 is the absence of a verdict — a sink
// that could not be reached or refused, no credential, a posture that could
// not be read. 7 and 10 never read as tamper detected, and every definitive
// verdict outranks them; 6 precedes 9 because the anchor is the verdict on
// the chain and the sink the verdict on a copy of a segment, and 7 precedes
// 10 for the same reason. 8 is no verdict on the chain at all: a seal's
// rotation did not complete, so the chain is intact and an operator step
// (agenthof audit seal) is owed; it is last, so a verdict on the chain is
// never hidden behind it, and a cron that watches the exit code does not
// see green while every writer is blocked.
const (
	exitAnchorMismatch     = 6
	exitAnchorUnverifiable = 7
	exitRotationIncomplete = 8
	exitSinkMismatch       = 9
	exitSinkUnverifiable   = 10
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

// anchorCredentialError marks a failure to resolve the anchor backend's
// credential. Its text is the broker's own, unchanged; the type lets a sweep
// tell a fault that recurs identically for every run from a log refusing one
// head.
type anchorCredentialError struct{ err error }

func (e *anchorCredentialError) Error() string { return e.err.Error() }
func (e *anchorCredentialError) Unwrap() error { return e.err }

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
			return "", &anchorCredentialError{errors.New("broker: token_exchange is not supported for an anchor backend")}
		}
	}
	d := broker.Dispatch{StaticEnv: broker.StaticEnv{}, ClientCredentials: broker.NewClientCredentials(client)}
	return func(ctx context.Context) (string, error) {
		tok, err := d.Resolve(ctx, ref)
		if err != nil {
			return "", &anchorCredentialError{err}
		}
		return tok, nil
	}
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

// anchorMode is which form of `audit anchor` a session serves: the control
// ledger's head (the shipped form) or a run's ledger. The preamble is shared;
// the mode decides only which posture key it reads and what it warns about.
type anchorMode int

const (
	anchorControl anchorMode = iota
	anchorRuns
)

// publicLogHosts are the well-known public transparency logs: a posture that
// names one publishes, for every run it anchors, an entry anyone can read.
var publicLogHosts = map[string]bool{"rekor.sigstore.dev": true}

// namesPublicLog reports whether the backend url's host is a well-known public
// log. An unparseable url is not one (Validate has already refused it).
func namesPublicLog(rawURL string) bool {
	u, err := url.Parse(rawURL)
	return err == nil && publicLogHosts[strings.ToLower(u.Hostname())]
}

// anchorSession is what every form of `audit anchor` shares once its preamble
// has passed: who invoked it, the posture, the pinned log key (nil =
// unpinned), and the writers. It is built only by openAnchorSession.
type anchorSession struct {
	controlLog string
	inv        identity.Invoker
	assertedAs string
	in         config.Integrity
	pub        *ecdsa.PublicKey // nil = unpinned
	keyMode    string           // "pinned" | "as served"
	timeout    time.Duration
	out        io.Writer
	logger     *slog.Logger // obs.New(stderr, …) as cmdRun builds it
}

// openAnchorSession runs the shipped preamble, in the shipped order:
//
//  1. the invoker (--token without AGENTHOF_OIDC_ISSUER → exit 2, unrecorded);
//  2. the posture (a fault → exit 2; the mode's key off or no file → exit 1,
//     unrecorded, zero network; on → its coordinates), then anchor.pub
//     (present and unusable → exit 2);
//  3. ledger writable (busy or damaged → exit 1, unrecorded);
//  4. a refused token → recorded refused;
//  5. the authorization read under installed.lock SHARED — exactly prune's;
//     network happens only past this line, so a refused caller causes no
//     public entry.
//
// It returns (nil, code) on every exit it took itself — refusals recorded
// exactly as today, head line printed — else the session, ready to submit.
func openAnchorSession(mode anchorMode, controlLog, as, groups, token string, timeout time.Duration, out, stderr io.Writer) (*anchorSession, int) {
	inv, assertedAs, refused, usageErr, verifyErr := resolveInvoker(as, groups, token)
	if usageErr {
		_, _ = fmt.Fprintln(out, "audit anchor: AGENTHOF_OIDC_ISSUER must be set in the environment to authenticate --token")
		return nil, 2
	}

	in, err := loadIntegrity(controlLog)
	if err != nil {
		_, _ = fmt.Fprintf(out, "audit anchor: %v\n", err)
		return nil, 2
	}
	switch mode {
	case anchorRuns:
		if in.AnchorRuns != "on-demand" {
			_, _ = fmt.Fprintf(out, "audit anchor: run anchoring is not configured in %s (anchor_runs: none); set anchor_runs: on-demand to anchor runs\n", integrityPath(controlLog))
			return nil, 1
		}
	default:
		if in.Anchor != "tlog" {
			_, _ = fmt.Fprintf(out, "audit anchor: no anchor configured in %s (anchor: none); set anchor: tlog and anchor_backend to anchor this ledger\n", integrityPath(controlLog))
			return nil, 1
		}
	}
	pub, err := pinnedLogKey(controlLog, "")
	if err != nil {
		_, _ = fmt.Fprintf(out, "audit anchor: %v\n", err)
		return nil, 2
	}
	keyMode := "as served"
	if pub != nil {
		keyMode = "pinned"
	}
	// The operational diagnostics channel: stderr, never out and never a
	// ledger record. Only the run-anchoring form emits on it, so the control
	// form neither reads the log environment nor can fail on it.
	logger := obs.New(stderr, slog.LevelInfo, obs.FormatText)
	if mode == anchorRuns {
		level, format, lerr := resolveLogConfig("", "", os.Getenv)
		if lerr != nil {
			_, _ = fmt.Fprintf(out, "audit anchor: %v\n", lerr)
			return nil, 2
		}
		logger = obs.New(stderr, level, format)
		if namesPublicLog(in.AnchorBackend.URL) {
			logger.Warn("anchor_backend names a public log; every anchored run becomes one public, permanent entry (its existence, timing and rate)", "backend", in.AnchorBackend.URL)
		}
		if pub == nil {
			logger.Warn("no anchor.pub beside the control ledger; anchored receipts read unverifiable from audit <run-id> until the log's key is pinned", "path", anchorPubPath(controlLog))
		}
	}
	if !controlLedgerWritable("audit anchor", controlLog, out) {
		return nil, 1
	}

	s := &anchorSession{controlLog: controlLog, inv: inv, assertedAs: assertedAs, in: in, pub: pub, keyMode: keyMode, timeout: timeout, out: out, logger: logger}

	if refused {
		_, _ = fmt.Fprintf(out, "audit anchor: token authentication failed: %v\n", verifyErr)
		return nil, s.recordFinish("refused", &control.Reason{Code: control.CodeTokenVerificationFailed, Message: "token verification failed"}, 1)
	}
	// The one read of the installed configuration — pointer, roles and the
	// ledger's vouch — under installed.lock SHARED, released before anything
	// is recorded or sent. Lock order store → ledger, as every reader.
	store := installedStore(controlLog)
	unlock, lockErr := ledger.LockFileShared(installedLock(controlLog))
	if lockErr != nil {
		if errors.Is(lockErr, ledger.ErrLockHeld) {
			_, _ = fmt.Fprintf(out, "audit anchor: %s\n", msgLockBusy)
			return nil, 1
		}
		_, _ = fmt.Fprintln(out, lockErr)
		return nil, s.recordFinish("error", &control.Reason{Code: control.CodeIOError, Message: truncateErr(lockErr)}, 1)
	}
	installedRoles, _, installed, refusal, instErr := func() (roles []config.RoleDef, hash string, installed bool, refusal *verifyRefusal, err error) {
		defer unlock()
		roles, hash, installed, err = config.InstalledRoles(store)
		if err != nil || !installed {
			return roles, hash, installed, nil, err
		}
		_, _, refusal = vouchInstalled(controlLog, hash)
		return roles, hash, installed, refusal, nil
	}()
	if instErr != nil {
		_, _ = fmt.Fprintln(out, instErr)
		_, _ = fmt.Fprint(out, installedHatch("audit anchor", "anchor", store))
		return nil, s.recordFinish("error", &control.Reason{Code: control.CodeIOError, Message: truncateErr(instErr)}, 1)
	}
	if !installed {
		_, _ = fmt.Fprintf(out, "audit anchor: %s\n", msgNothingInstalled)
		_, _ = fmt.Fprintf(out, "%s under %s; run: agenthof apply --config <dir> --control-log %s\n", msgNoConfigInstalled, store, controlLog)
		return nil, s.recordFinish("refused", &control.Reason{Code: control.CodeNotAuthorized, Message: msgNothingInstalled}, 1)
	}
	if refusal != nil {
		switch {
		case refusal.Transient():
			_, _ = fmt.Fprintf(out, "audit anchor: %s\n", msgLockBusy)
			return nil, 1
		case refusal.Kind != verifyNotOnRecord:
			_, _ = fmt.Fprintf(out, "audit anchor: %s\n", refusal.Error())
			return nil, 1
		}
		_, _ = fmt.Fprintf(out, "audit anchor: %s\n", refusal.Error())
		return nil, s.recordFinish("refused", vouchRefused(refusal), 1)
	}
	if !authz.ControlAllows(installedRoles, inv, "anchor") {
		reason := control.NotAuthorized("anchor")
		_, _ = fmt.Fprintf(out, "audit anchor: %s\n", reason.Message)
		return nil, s.recordFinish("refused", reason, 1)
	}
	return s, 0
}

// record appends one anchor record — the invoker, the witness, the payload if
// any — and returns the head it produced. It prints nothing: the caller owns
// the order of what reaches stdout.
func (s *anchorSession) record(outcome string, reason *control.Reason, payload *control.Anchor) (ledger.Head, error) {
	return control.Append(s.controlLog, control.Event{
		Action: "anchor", Outcome: outcome, Reason: reason,
		Invoker: s.inv, AssertedAs: s.assertedAs, Witness: control.CaptureWitness(),
		Anchor: payload,
	})
}

// finish prints the shipped lines, then "control head: seq=K sha256=H" — the
// order every control writer prints last — and returns code.
func (s *anchorSession) finish(shipped []string, head ledger.Head, code int) int {
	for _, l := range shipped {
		_, _ = fmt.Fprintln(s.out, l)
	}
	_, _ = fmt.Fprintf(s.out, "control head: seq=%d sha256=%s\n", head.Count, head.Hash)
	return code
}

// recordFinish is a payload-less record followed by its head line: the shape
// of every refusal and error the preamble records. A failed append prints the
// error and is exit 1, with no head line for a record that did not land.
func (s *anchorSession) recordFinish(outcome string, reason *control.Reason, code int) int {
	head, err := s.record(outcome, reason, nil)
	if err != nil {
		_, _ = fmt.Fprintln(s.out, err)
		return 1
	}
	return s.finish(nil, head, code)
}

// cmdAuditAnchor is `audit anchor`: pin the control ledger's current head
// into the transparency log the root's integrity.yaml names, and record on
// the chain which head was pinned, where the log's entry is, the log's proof
// and which log key signed for it. The preamble is openAnchorSession's
// (steps 1–5); this is what follows, in order:
//
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
//
// With --run <run-id> (or --pending) the same preamble serves the run form
// instead: the id is shape-checked right after flag parsing, before the
// posture or any path is read, and anchorRuns takes the run-anchoring lock and
// anchors a finished run's final head, writing the proof beside the run.
func cmdAuditAnchor(args []string, out, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit anchor", flag.ContinueOnError)
	controlLog := fs.String("control-log", ".agenthof/control.jsonl", "control-plane ledger path; integrity.yaml and anchor.pub are read from beside it")
	as := fs.String("as", "", "invoker identity (defaults to the OS user); ignored when --token is given")
	groups := fs.String("groups", "", "comma-separated groups asserted for the --as identity; DEV ONLY — self-asserted, not verified, ignored when --token is given")
	token := fs.String("token", "", "raw OIDC token to authenticate the invoker (env AGENTHOF_TOKEN fallback); a production cron presents this, not --as/--groups")
	timeout := fs.Duration("timeout", 30*time.Second, "bound on the whole exchange with the log")
	runID := fs.String("run", "", "anchor this finished run's ledger (needs anchor_runs: on-demand); the proof is written beside it as <run-id>.anchor")
	pending := fs.Bool("pending", false, "anchor every finished run not yet anchored, up to --limit (needs anchor_runs: on-demand)")
	limit := fs.Int("limit", 50, "with --pending: the most runs to anchor in one pass")
	logDir := fs.String("log-dir", ".agenthof/runs", "run log directory (--run and --pending)")
	fs.SetOutput(out)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	runSet := false // --run "" is a bad id, not an absent flag
	fs.Visit(func(f *flag.Flag) { runSet = runSet || f.Name == "run" })
	if runSet && *pending {
		_, _ = fmt.Fprintln(out, "audit anchor: --run and --pending are mutually exclusive")
		return 2
	}
	if *limit <= 0 {
		_, _ = fmt.Fprintln(out, "audit anchor: --limit must be positive")
		return 2
	}
	// The shape check precedes the posture, the lock and every path: a value
	// that is not a run id never reaches a file name.
	if runSet && !sidecar.RunIDRE.MatchString(*runID) {
		_, _ = fmt.Fprintf(out, "audit anchor: --run %q is not a run id (want r- followed by 16 lowercase hex)\n", *runID)
		return 1
	}
	mode := anchorControl
	if runSet || *pending {
		mode = anchorRuns
	}
	s, code := openAnchorSession(mode, *controlLog, *as, *groups, *token, *timeout, out, stderr)
	if s == nil {
		return code
	}
	if mode == anchorRuns {
		return s.anchorRuns(runAnchorOpts{logDir: *logDir, runID: *runID, pending: *pending, limit: *limit})
	}
	return s.anchorControlHead()
}

// receiptLines are the two lines every anchoring form ships after its
// "anchored…" line: where the entry is and which log key signed for it (named
// pinned or as served), then what the log reported about it — all of it as
// reported by the log, none of it a verdict.
func receiptLines(rcpt anchor.Receipt, keyMode string) (logLine, indexLine string) {
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
	return fmt.Sprintf("  log: %s  entry: %s  log key: %s (%s)", rcpt.Backend, rcpt.Ref, keyID, keyMode),
		fmt.Sprintf("  index: %s  integrated: %s  (as reported by the log)", index, integrated)
}

// anchorControlHead is the control form's body: the head, the submit, the
// record, the shipped lines.
func (s *anchorSession) anchorControlHead() int {
	out, in := s.out, s.in
	// The head. installed.lock is released; the record carries (seq, hash)
	// explicitly, so the head is free to advance under us.
	v, err := control.Read(s.controlLog, ledger.Locked)
	if err != nil {
		_, _ = fmt.Fprintf(out, "audit anchor: %v\n", err)
		return 1
	}
	head := v.Head
	if head.Count == 0 {
		_, _ = fmt.Fprintln(out, "audit anchor: the control ledger is empty; nothing to anchor")
		return 1
	}
	covered := anchor.Head{Seq: head.Count, Hash: head.Hash}
	tried := &control.Anchor{Seq: covered.Seq, Hash: covered.Hash, Kind: "tlog", BackendKind: in.AnchorBackend.Kind, Backend: strings.TrimSuffix(in.AnchorBackend.URL, "/")}
	failed := func(err error) int {
		_, _ = fmt.Fprintf(out, "audit anchor: %v\n", err)
		h, appendErr := s.record("error", &control.Reason{Code: control.CodeAnchorFailed, Message: truncateErr(err)}, tried)
		if appendErr != nil {
			_, _ = fmt.Fprintln(out, appendErr)
			return 1
		}
		return s.finish(nil, h, 1)
	}

	// Network happens only from here.
	be, err := newAnchorBackend(backendSpec{Kind: in.AnchorBackend.Kind, URL: in.AnchorBackend.URL, Key: s.pub, Credential: in.AnchorBackend.Credential})
	if err != nil {
		return failed(err)
	}
	tried.BackendKind = be.Kind()
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	rcpt, err := be.Submit(ctx, covered)
	cancel()
	if err != nil {
		return failed(err)
	}

	payload := &control.Anchor{Seq: covered.Seq, Hash: covered.Hash, Kind: "tlog", BackendKind: be.Kind(), Backend: rcpt.Backend, Ref: rcpt.Ref, Proof: rcpt.Proof, BackendKeyID: rcpt.BackendKeyID}
	logLine, indexLine := receiptLines(rcpt, s.keyMode)
	// Record first: the printed lines are the artifact the cron ships, and a
	// head line for a record that did not land would be a lie. finish prints
	// shipped, then the head — the spec's order.
	shipped := []string{
		fmt.Sprintf("anchored: seq=%d sha256=%s", covered.Seq, covered.Hash),
		logLine,
		indexLine,
	}
	recorded, appendErr := s.record("success", nil, payload)
	if appendErr != nil {
		_, _ = fmt.Fprintln(out, appendErr)
		_, _ = fmt.Fprintf(out, "audit anchor: anchored at %s but NOT recorded\n", payload.Ref)
		return 1
	}
	return s.finish(shipped, recorded, 0)
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

// investigateOptions is the anchor-verdict wiring investigate and serve hand
// investigate.Timeline: the pin resolved exactly as audit verify control
// resolves it (--anchor-key, else anchor.pub beside the ledger, else
// unpinned; a key that cannot be loaded is a per-anchor verdict, never exit
// 2), and the verify-side backend through the newAnchorBackend seam. serve
// passes anchorKey == "": its pin is the anchor.pub beside its own ledger,
// resolved per request.
func investigateOptions(controlLog, anchorKey string) investigate.Options {
	return investigate.Options{
		AnchorKey:     func() (*ecdsa.PublicKey, error) { return pinnedLogKey(controlLog, anchorKey) },
		AnchorBackend: verifyBackendFactory,
	}
}
