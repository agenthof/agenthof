package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/agenthof/agenthof/internal/agentcard"
	"github.com/agenthof/agenthof/internal/authz"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/ledger"
	"github.com/agenthof/agenthof/internal/origin"
	"github.com/agenthof/agenthof/internal/registry"
)

const (
	// enrollInterface is the one agent-card interface marker enroll accepts:
	// the artifact speaks the A2A protocol Agenthof's fronted adapter drives.
	enrollInterface = "a2a"

	// enrollFetchTimeout bounds fetching a card over https.
	enrollFetchTimeout = 30 * time.Second

	// maxEnrollRedirects bounds same-host redirects while fetching a card.
	maxEnrollRedirects = 3

	// maxEnrollVersionLen bounds the card's declared version as recorded in
	// the agent's provenance.
	maxEnrollVersionLen = 64

	msgEnrollSignature = "agent card signature did not verify against a trusted signer"
	msgEnrollDeclined  = "the accepted digest does not match the card"
)

// enrollNameRE is the shape of an enrolled agent's name. It is refspawn's
// compartment-name grammar (deploy/refspawn nameRE), because the name is also
// the supervisor's images: key and the enrolled workflow and role names; it
// cannot hold a path separator, so it is safe as a file name.
var enrollNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

// maxEnrollName matches refspawn's maxName.
const maxEnrollName = 64

// enrollArtifactRE is a pinned artifact reference: <ref>@sha256:<64 hex>, no
// whitespace. A tag-only reference moves under the operator; a digest does not.
var enrollArtifactRE = regexp.MustCompile(`^[A-Za-z0-9._:/+-]+@sha256:[0-9a-f]{64}$`)

// enrollVersionRE is the grammar of the card version recorded in provenance
// and the written description: conservative, so it can never read as prose.
var enrollVersionRE = regexp.MustCompile(`^[A-Za-z0-9._+-]{0,64}$`)

// enrollAppend records the success event; a variable so a test can fail it.
var enrollAppend = control.Append

// acceptRE is --accept's grammar, and the form the card digest is printed in.
var acceptRE = regexp.MustCompile(`^sha256:([0-9a-f]{64})$`)

// enrollHTTPClient fetches https card sources; tests replace it.
var enrollHTTPClient = &http.Client{Timeout: enrollFetchTimeout}

// parseAccept returns the hex digest of a well-formed --accept value.
func parseAccept(v string) (string, bool) {
	m := acceptRE.FindStringSubmatch(v)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// checkAccept is the consent gate: the digest the operator accepted must be
// the digest of the card as it was just re-fetched and verified. An empty card
// digest (a failure to compute one) never matches.
func checkAccept(accept, cardDigest string) error {
	want, ok := parseAccept(accept)
	if !ok {
		return errors.New("--accept must be sha256:<64 lowercase hex digits>")
	}
	if cardDigest == "" || want != cardDigest {
		return errors.New(msgEnrollDeclined)
	}
	return nil
}

// checkEnrollName validates --name against the name grammar and refuses a
// name any given configuration already uses as an agent, workflow or role
// (compared case-insensitively: a case-folding filesystem would collide them).
func checkEnrollName(name string, cfgs ...config.Config) error {
	if !enrollNameRE.MatchString(name) || len(name) > maxEnrollName {
		return fmt.Errorf("--name %q must match %s and be at most %d characters", origin.Clean(name), enrollNameRE, maxEnrollName)
	}
	for _, cfg := range cfgs {
		for _, a := range cfg.Agents {
			if strings.EqualFold(a.Name, name) {
				return fmt.Errorf("name %q is already an agent in the configuration", name)
			}
		}
		for _, w := range cfg.Workflows {
			if strings.EqualFold(w.Name, name) {
				return fmt.Errorf("name %q is already a workflow in the configuration", name)
			}
		}
		for _, r := range cfg.Roles {
			if strings.EqualFold(r.Name, name) {
				return fmt.Errorf("name %q is already a role in the configuration", name)
			}
		}
	}
	return nil
}

// fetchCard reads a card from a local file or an https URL — nothing else: no
// http, no file://, no ssh or git transport. A URL is fetched with a timeout,
// a size cap, no credentials in the URL, and no redirect to another host or
// off https. It never runs git; a git repository of cards is cloned by the
// operator and a file inside it named.
func fetchCard(source string, client *http.Client) ([]byte, error) {
	if source == "" {
		return nil, errors.New("no card source: name a local file or an https URL")
	}
	if strings.Contains(source, "://") {
		return fetchCardURL(source, client)
	}
	f, err := os.Open(source)
	if err != nil {
		return nil, fmt.Errorf("read card: %w", err)
	}
	defer func() { _ = f.Close() }()
	// Judge the handle we opened, not the path: no check-then-open window.
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("read card: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("card source %q is not a regular file", origin.Clean(source))
	}
	return readCardBody(f)
}

func fetchCardURL(source string, client *http.Client) ([]byte, error) {
	u, err := url.Parse(source)
	if err != nil {
		return nil, errors.New("card source is not a valid URL")
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("card source scheme %q is not supported; use a local file or an https URL", origin.Clean(u.Scheme))
	}
	if u.Host == "" || u.User != nil {
		return nil, errors.New("card source URL needs a host and must carry no credentials")
	}
	c := *client
	if c.Timeout == 0 {
		c.Timeout = enrollFetchTimeout
	}
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" || req.URL.Host != via[0].URL.Host {
			return errors.New("refusing a redirect to another host")
		}
		if len(via) > maxEnrollRedirects {
			return fmt.Errorf("refusing a redirect chain longer than %d", maxEnrollRedirects)
		}
		return nil
	}
	resp, err := c.Get(u.String())
	if err != nil {
		return nil, fmt.Errorf("fetch card: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch card: server answered %d", resp.StatusCode)
	}
	return readCardBody(resp.Body)
}

// readCardBody reads at most MaxCardBytes, and refuses more.
func readCardBody(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, agentcard.MaxCardBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read card: %w", err)
	}
	if len(b) > agentcard.MaxCardBytes {
		return nil, fmt.Errorf("agent card is over the %d byte limit", agentcard.MaxCardBytes)
	}
	return b, nil
}

// enrollFile is one new config file: its path relative to the config
// directory (slash-separated) and its exact bytes.
type enrollFile struct {
	rel  string
	data []byte
}

// writeNewFiles creates each file under root, only if it does not already
// exist, in the order given. Each file is written whole to a temp name
// (which configFiles never enumerates) and then hard-linked into place, so it
// appears complete and atomically, and a name that exists is never overwritten.
// If any file cannot be created, the files this call created are removed and
// the error is returned. It returns each file's path and sha256.
func writeNewFiles(root string, files []enrollFile) ([]control.EnrollFile, error) {
	var made []string
	rollback := func() {
		for _, p := range made {
			_ = os.Remove(p)
		}
	}
	var rec []control.EnrollFile
	for _, f := range files {
		final := filepath.Join(root, filepath.FromSlash(f.rel))
		if err := os.MkdirAll(filepath.Dir(final), 0o755); err != nil {
			rollback()
			return nil, err
		}
		tmp, err := os.CreateTemp(filepath.Dir(final), ".enroll-*.tmp")
		if err != nil {
			rollback()
			return nil, err
		}
		_, werr := tmp.Write(f.data)
		if werr == nil {
			werr = tmp.Sync()
		}
		if cerr := tmp.Close(); werr == nil {
			werr = cerr
		}
		if werr == nil {
			werr = os.Chmod(tmp.Name(), 0o644)
		}
		if werr == nil {
			werr = os.Link(tmp.Name(), final)
		}
		_ = os.Remove(tmp.Name())
		if werr != nil {
			rollback()
			return nil, fmt.Errorf("create %s: %w", f.rel, werr)
		}
		made = append(made, final)
		sum := sha256.Sum256(f.data)
		rec = append(rec, control.EnrollFile{Path: f.rel, SHA256: hex.EncodeToString(sum[:])})
	}
	return rec, nil
}

// Minimal write shapes: only what an enrollment sets, so the file the
// operator reviews holds no empty endpoint, exec or may_spawn keys.
type enrollAgentYAML struct {
	Name        string             `yaml:"name"`
	Description string             `yaml:"description"`
	Model       string             `yaml:"model,omitempty"`
	Tools       []config.ToolGrant `yaml:"tools,omitempty"`
	Provenance  *config.Provenance `yaml:"provenance"`
}

type enrollStepYAML struct {
	Name  string `yaml:"name"`
	Agent string `yaml:"agent"`
}

type enrollWorkflowYAML struct {
	Name        string           `yaml:"name"`
	Description string           `yaml:"description"`
	Steps       []enrollStepYAML `yaml:"steps"`
}

type enrollRoleYAML struct {
	Name          string   `yaml:"name"`
	Description   string   `yaml:"description"`
	Workflows     []string `yaml:"workflows"`
	AllowedGroups []string `yaml:"allowed_groups"`
}

// cleanCardString refuses a card string that holds invalid UTF-8 or a
// non-printable rune — exactly the text origin.Clean would drop — rather than
// silently altering it, so the bytes disclosed are the bytes written. Length
// is bounded separately, by the caps the ledger itself enforces.
func cleanCardString(what, s string) error {
	for _, r := range s {
		if r == utf8.RuneError || !unicode.IsPrint(r) {
			return fmt.Errorf("agent card %s holds non-printable text", what)
		}
	}
	return nil
}

// enrollRefusal prints a refusal, with card-derived text cleaned.
func enrollRefusal(w io.Writer, format string, a ...any) int {
	_, _ = fmt.Fprintf(w, "enroll: "+format+"\n", a...)
	return 1
}

// cmdEnroll is `enroll <source>`: fetch a curator-signed A2A agent card,
// verify it against the gateway's trusted signers, map it to a proposed
// spawn-only agent, and disclose exactly what would be written. Without
// --accept nothing is written or recorded. With --accept sha256:<digest> the
// card is re-fetched and re-verified, and only if it is the same signed
// content are the new agent, workflow and role files created (never
// overwriting a file) and the enrollment recorded. It never edits an existing
// file: the may_spawn line and the supervisor images: line are printed for the
// operator to add by hand.
func cmdEnroll(argv []string, stdout, stderr io.Writer) int {
	source := ""
	if len(argv) > 0 && !strings.HasPrefix(argv[0], "-") {
		source, argv = argv[0], argv[1:]
	}
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	name := fs.String("name", "", "name for the enrolled agent, its workflow and its dedicated role (required)")
	role := fs.String("role", "", "installed role whose allowed_groups the enrolled agent's dedicated role inherits (required)")
	accept := fs.String("accept", "", "consent: proceed only if the card's digest is this sha256:<hex>, as disclosed by a run without --accept")
	cfgDir := fs.String("config", "./config", "configuration directory the new files are written into")
	controlLog := fs.String("control-log", ".agenthof/control.jsonl", "control-plane ledger path; the installed configuration is read from installed/ beside it")
	as := fs.String("as", "", "invoker identity (defaults to the OS user); ignored when --token is given")
	groups := fs.String("groups", "", "comma-separated groups asserted for the --as identity; DEV ONLY — self-asserted, not verified, ignored when --token is given")
	token := fs.String("token", "", "raw OIDC token to authenticate the invoker (env AGENTHOF_TOKEN fallback); when set, identity comes from the token, not --as/--groups")
	fs.SetOutput(stderr)
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	if source == "" && fs.NArg() == 1 {
		source = fs.Arg(0)
	} else if fs.NArg() > 0 {
		_, _ = fmt.Fprintln(stderr, "enroll: one card source (a local file or https URL) is expected")
		return 2
	}
	if source == "" || *name == "" || *role == "" {
		_, _ = fmt.Fprintln(stderr, "enroll: usage: agenthof enroll <card file|https URL> --name <name> --role <role> [--accept sha256:<hex>]")
		return 2
	}
	if err := checkEnrollName(*name); err != nil {
		_, _ = fmt.Fprintf(stderr, "enroll: %v\n", err)
		return 2
	}
	var acceptDigest string
	if *accept != "" {
		d, ok := parseAccept(*accept)
		if !ok {
			_, _ = fmt.Fprintln(stderr, "enroll: --accept must be sha256:<64 lowercase hex digits>")
			return 2
		}
		acceptDigest = d
	}

	inv, assertedAs, refused, usageErr, verifyErr := resolveInvoker(*as, *groups, *token)
	if usageErr {
		_, _ = fmt.Fprintln(stderr, "enroll: AGENTHOF_OIDC_ISSUER must be set in the environment to authenticate --token")
		return 2
	}
	if !controlLedgerWritable("enroll", *controlLog, stderr) {
		return 1
	}

	// record appends one enroll event and prints the head. An append that
	// fails is printed; the exit code is then 1 whatever was intended.
	record := func(outcome string, reason *control.Reason, payload *control.Enroll, code int) int {
		head, err := control.Append(*controlLog, control.Event{
			Action:     "enroll",
			Agent:      *name,
			Outcome:    outcome,
			Reason:     reason,
			Invoker:    inv,
			AssertedAs: assertedAs,
			Witness:    control.CaptureWitness(),
			Enroll:     payload,
		})
		if err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "control head: seq=%d sha256=%s\n", head.Count, head.Hash)
		return code
	}

	if refused {
		// The recorded reason is fixed: the OIDC error can echo claim values.
		_, _ = fmt.Fprintf(stderr, "enroll: token authentication failed: %v\n", verifyErr)
		return record("refused", &control.Reason{Code: control.CodeTokenVerificationFailed, Message: "token verification failed"}, nil, 1)
	}

	// The installed configuration: its roles authorize, its gateway holds the
	// trust anchors and the tool/model catalog. Read once, verified against
	// its pointer, under the shared lock, with the ledger's vouch.
	store := installedStore(*controlLog)
	unlock, lockErr := ledger.LockFileShared(installedLock(*controlLog))
	if lockErr != nil {
		if errors.Is(lockErr, ledger.ErrLockHeld) {
			return enrollRefusal(stderr, "%s", msgLockBusy)
		}
		_, _ = fmt.Fprintln(stderr, lockErr)
		return record("error", &control.Reason{Code: control.CodeIOError, Message: truncateErr(lockErr)}, nil, 1)
	}
	instCfg, hash, installed, instErrs, refusal := func() (config.Config, string, bool, []error, *verifyRefusal) {
		defer unlock()
		cfg, h, ok, errs := config.LoadInstalled(store)
		if len(errs) > 0 || !ok {
			return cfg, h, ok, errs, nil
		}
		_, _, rf := vouchInstalled(*controlLog, h)
		return cfg, h, ok, nil, rf
	}()
	if len(instErrs) > 0 {
		for _, e := range instErrs {
			_, _ = fmt.Fprintln(stderr, e)
		}
		_, _ = fmt.Fprint(stderr, installedHatch("enroll", "enroll", store))
		return record("error", &control.Reason{Code: control.CodeIOError, Message: truncateErr(instErrs[0])}, nil, 1)
	}
	if !installed {
		_, _ = fmt.Fprintf(stderr, "enroll: %s\n", msgNothingInstalled)
		_, _ = fmt.Fprintf(stderr, "%s under %s; run: agenthof apply --config <dir> --control-log %s\n", msgNoConfigInstalled, store, *controlLog)
		return record("refused", &control.Reason{Code: control.CodeNotAuthorized, Message: msgNothingInstalled}, nil, 1)
	}
	if refusal != nil {
		switch {
		case refusal.Transient():
			return enrollRefusal(stderr, "%s", msgLockBusy)
		case refusal.Kind != verifyNotOnRecord:
			return enrollRefusal(stderr, "%s", refusal.Error())
		}
		_, _ = fmt.Fprintf(stderr, "enroll: %s\n", refusal.Error())
		return record("refused", vouchRefused(refusal), nil, 1)
	}
	if !authz.ControlAllows(instCfg.Roles, inv, "enroll") {
		reason := control.NotAuthorized("enroll")
		_, _ = fmt.Fprintf(stderr, "enroll: %s\n", reason.Message)
		return record("refused", reason, nil, 1)
	}

	// Preconditions that need no card. Not recorded: nothing was decided.
	if len(instCfg.Gateway.TrustedSigners) == 0 {
		return enrollRefusal(stderr, "no trusted signers are configured: add trusted_signers (kid and key) to gateway.yaml and apply it; enroll never trusts a card by default")
	}
	var anchors []agentcard.Anchor
	for _, ts := range instCfg.Gateway.TrustedSigners {
		key, err := ts.PublicKey()
		if err != nil {
			return enrollRefusal(stderr, "the installed trusted_signers entry %q is unusable: %v", origin.Clean(ts.KID), err)
		}
		anchors = append(anchors, agentcard.Anchor{KID: ts.KID, Key: key})
	}
	var owner *config.RoleDef
	for i := range instCfg.Roles {
		if instCfg.Roles[i].Name == *role {
			owner = &instCfg.Roles[i]
		}
	}
	if owner == nil {
		return enrollRefusal(stderr, "--role %q is not an installed role", origin.Clean(*role))
	}
	workCfg, loadErrs := config.LoadDir(*cfgDir)
	if len(loadErrs) > 0 {
		for _, e := range loadErrs {
			_, _ = fmt.Fprintln(stderr, origin.Clean(e.Error()))
		}
		return enrollRefusal(stderr, "the configuration in %s does not load; fix it before enrolling", *cfgDir)
	}
	if err := checkEnrollName(*name, workCfg, instCfg); err != nil {
		return enrollRefusal(stderr, "%v", err)
	}

	// Fetch and parse. Failures here are the operator's input, not a
	// decision on record: nothing is recorded.
	raw, err := fetchCard(source, enrollHTTPClient)
	if err != nil {
		return enrollRefusal(stderr, "%s", origin.Clean(err.Error()))
	}
	card, err := agentcard.Parse(raw)
	if err != nil {
		return enrollRefusal(stderr, "%s", origin.Clean(err.Error()))
	}

	// Verify BEFORE reading anything out of the card: only a verified card
	// is acted on. The error text can carry card-supplied strings, so it is
	// printed cleaned and never recorded.
	kid, err := agentcard.Verify(card, anchors)
	digest := card.SignedDigest()
	if err == nil && digest == "" {
		err = errors.New("the signed card body could not be digested")
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "enroll: %s\n", origin.Clean(err.Error()))
		return record("refused", &control.Reason{Code: control.CodeSignatureFailure, Message: msgEnrollSignature}, nil, 1)
	}

	ext, err := card.Extension()
	if err != nil {
		return enrollRefusal(stderr, "%s", origin.Clean(err.Error()))
	}
	if ext.Interface != enrollInterface {
		return enrollRefusal(stderr, "the card's interface %q is not supported; want %q", origin.Clean(ext.Interface), enrollInterface)
	}
	// Each artifact form present is judged on its own; the card parse has
	// already refused a card naming neither. The host-program form's shape is
	// checked there and again when the event is recorded.
	if ext.Artifact == "" && ext.HostProgram == nil {
		return enrollRefusal(stderr, "the card names no artifact: it needs an image, a host program, or both")
	}
	if ext.Artifact != "" && (!enrollArtifactRE.MatchString(ext.Artifact) || len(ext.Artifact) > control.MaxEnrollArtifactLen) {
		return enrollRefusal(stderr, "the card's artifact %q is not pinned to a digest (want <ref>@sha256:<64 hex>)", origin.Clean(ext.Artifact))
	}
	if !enrollVersionRE.MatchString(card.Version) {
		return enrollRefusal(stderr, "the card's version must be at most %d characters of A-Z a-z 0-9 . _ + -", maxEnrollVersionLen)
	}
	tools, models := map[string]bool{}, map[string]bool{}
	for id := range instCfg.Gateway.Tools {
		tools[id] = true
	}
	for id := range instCfg.Gateway.Models {
		models[id] = true
	}
	def, requested, err := agentcard.Map(ext, *name, tools, models)
	if err != nil {
		return enrollRefusal(stderr, "%s", origin.Clean(err.Error()))
	}
	if def.Model == "" {
		// No model requested: the model door falls back to the gateway's
		// default, so the agent gets it. Disclose that implicit grant and
		// record it with the rest of what the card is enrolled for.
		if dm := instCfg.Gateway.Defaults.Model; dm != "" {
			requested = append(requested, fmt.Sprintf("model %s (gateway default; not requested)", dm))
		} else {
			requested = append(requested, "no model (none requested and no gateway default is configured)")
		}
	}
	if len(requested) > control.MaxEnrollRequested {
		return enrollRefusal(stderr, "the card requests %d capabilities; the most one enrollment records is %d", len(requested), control.MaxEnrollRequested)
	}
	for _, r := range requested {
		if len(r) > control.MaxEnrollRequestedLen {
			return enrollRefusal(stderr, "a requested capability is longer than %d bytes", control.MaxEnrollRequestedLen)
		}
		if err := cleanCardString("request", r); err != nil {
			return enrollRefusal(stderr, "%v", err)
		}
	}

	// The files, marshaled once: the bytes disclosed are the bytes written.
	def.Provenance.CardSHA256 = digest
	def.Provenance.CardVersion = card.Version
	files, err := enrollFiles(*name, def, owner.AllowedGroups)
	if err != nil {
		return enrollRefusal(stderr, "%v", err)
	}

	// The written set must pass the same validation apply runs, over the
	// configuration directory plus the new files.
	newWF, err1 := enrollReload[config.WorkflowDef](files[0].data, files[0].rel)
	newRole, err2 := enrollReload[config.RoleDef](files[1].data, files[1].rel)
	newAgent, err3 := enrollReload[config.AgentDef](files[2].data, files[2].rel)
	if err := errors.Join(err1, err2, err3); err != nil {
		return enrollRefusal(stderr, "%v", err)
	}
	candidate := config.Config{
		Agents:    append(append([]config.AgentDef(nil), workCfg.Agents...), newAgent),
		Workflows: append(append([]config.WorkflowDef(nil), workCfg.Workflows...), newWF),
		Roles:     append(append([]config.RoleDef(nil), workCfg.Roles...), newRole),
		Gateway:   workCfg.Gateway,
	}
	if _, verrs := registry.Build(candidate); len(verrs) > 0 {
		for _, e := range verrs {
			_, _ = fmt.Fprintln(stderr, origin.Clean(e.Error()))
		}
		return enrollRefusal(stderr, "the enrolled agent would not pass validation in %s; nothing was written", *cfgDir)
	}

	payload := &control.Enroll{
		CardSHA256: digest,
		Artifact:   ext.Artifact,
		Requested:  requested,
		SignerKID:  kid,
	}
	if hp := ext.HostProgram; hp != nil {
		payload.HostProgram = &control.EnrollHostProgram{Program: hp.Program}
		for _, b := range hp.Builds {
			payload.HostProgram.Builds = append(payload.HostProgram.Builds, control.EnrollHostBuild{OS: b.OS, Arch: b.Arch, SHA256: b.SHA256})
		}
	}

	// Disclose.
	_, _ = fmt.Fprintf(stdout, "enroll: proposed spawn-only agent %q\n", *name)
	_, _ = fmt.Fprintf(stdout, "card digest: sha256:%s\n", digest)
	_, _ = fmt.Fprintf(stdout, "signed by:   %s\n", origin.Clean(kid))
	if ext.Artifact != "" {
		_, _ = fmt.Fprintf(stdout, "artifact:    %s (recorded; not yet enforced at launch)\n", ext.Artifact)
	}
	if hp := ext.HostProgram; hp != nil {
		_, _ = fmt.Fprintf(stdout, "program:     %s (a logical id, not a path; recorded; not yet enforced at launch)\n", origin.Clean(hp.Program))
		for _, b := range hp.Builds {
			_, _ = fmt.Fprintf(stdout, "  build %s/%s %s\n", origin.Clean(b.OS), origin.Clean(b.Arch), origin.Clean(b.SHA256))
		}
	}
	_, _ = fmt.Fprintln(stdout, "requested:")
	for _, r := range requested {
		_, _ = fmt.Fprintf(stdout, "  - %s\n", r)
	}
	_, _ = fmt.Fprintf(stdout, "files to create under %s (existing files are never changed):\n", *cfgDir)
	for _, f := range files {
		_, _ = fmt.Fprintf(stdout, "--- %s\n%s", f.rel, f.data)
	}
	if *accept == "" {
		_, _ = fmt.Fprintf(stdout, "nothing written. To enroll exactly this card, run again with: --accept sha256:%s\n", digest)
		return 0
	}

	// Consent: the re-fetched, re-verified card must be the one accepted.
	if err := checkAccept("sha256:"+acceptDigest, digest); err != nil {
		_, _ = fmt.Fprintf(stderr, "enroll: %v; nothing written\n", err)
		return record("refused", &control.Reason{Code: control.CodeConsentDeclined, Message: msgEnrollDeclined}, payload, 1)
	}

	// Write, under the installed-configuration lock, and only if the
	// installed configuration is still the one this decision was made
	// against.
	wunlock, lockErr := ledger.LockFile(installedLock(*controlLog))
	if lockErr != nil {
		if errors.Is(lockErr, ledger.ErrLockHeld) {
			return enrollRefusal(stderr, "%s", msgLockBusy)
		}
		return enrollRefusal(stderr, "%v", lockErr)
	}
	defer wunlock()
	if cur, ok, err := config.InstalledHash(store); err != nil || !ok || cur != hash {
		return enrollRefusal(stderr, "the installed configuration changed while enrolling; nothing written; run again")
	}
	written, err := writeNewFiles(*cfgDir, files)
	if err != nil {
		return enrollRefusal(stderr, "%v; nothing written", err)
	}
	payload.Files = written
	head, err := enrollAppend(*controlLog, control.Event{
		Action:     "enroll",
		Agent:      *name,
		Outcome:    "success",
		Invoker:    inv,
		AssertedAs: assertedAs,
		Witness:    control.CaptureWitness(),
		Enroll:     payload,
	})
	if err != nil {
		// Best effort: remove what this run created so a refused record
		// leaves no unrecorded enrollment. A crash between the write and the
		// append, or a failed removal, can still leave files the ledger does
		// not know of; that is bounded because apply is its own recorded act.
		for _, f := range written {
			_ = os.Remove(filepath.Join(*cfgDir, filepath.FromSlash(f.Path)))
		}
		_, _ = fmt.Fprintln(stderr, err)
		return enrollRefusal(stderr, "the enrollment could not be recorded; the files were removed")
	}
	_, _ = fmt.Fprintf(stdout, "enrolled %q: %d files created under %s\n", *name, len(written), *cfgDir)
	_, _ = fmt.Fprintf(stdout, "control head: seq=%d sha256=%s\n", head.Count, head.Hash)
	_, _ = fmt.Fprintf(stdout, "next, by hand (granting a trusted agent the right to launch untrusted code is your edit to make):\n")
	_, _ = fmt.Fprintf(stdout, "  1. in the trusted orchestrator's agent file, add:\n       may_spawn:\n         - role: %q\n           workflow: %q\n", *name, *name)
	_, _ = fmt.Fprintf(stdout, "  2. in the spawn supervisor's config, add under images: (one entry per isolation tier you run)\n")
	if ext.Artifact != "" {
		_, _ = fmt.Fprintf(stdout, "       podman (a digest-pinned image reference):\n         %q: %q\n", *name, ext.Artifact)
	}
	if hp := ext.HostProgram; hp != nil {
		_, _ = fmt.Fprintf(stdout, "       seatbelt (program %q: map it to your local path to the executable; its sha256 must be one of):\n", origin.Clean(hp.Program))
		for _, b := range hp.Builds {
			_, _ = fmt.Fprintf(stdout, "         %s/%s %s\n", origin.Clean(b.OS), origin.Clean(b.Arch), origin.Clean(b.SHA256))
		}
	}
	_, _ = fmt.Fprintf(stdout, "  3. review, then: agenthof apply --config %s\n", *cfgDir)
	return 0
}

// enrollFiles marshals the three new files for an enrolled agent, in the
// order they are written: workflow, role, then the agent last (so an agent
// file exists only once everything it needs does). groups are the owner
// role's allowed_groups, copied to the dedicated role.
func enrollFiles(name string, def config.AgentDef, groups []string) ([]enrollFile, error) {
	wf, err := yaml.Marshal(enrollWorkflowYAML{
		Name:        name,
		Description: "Runs the enrolled agent " + name + " as a spawned child",
		Steps:       []enrollStepYAML{{Name: "run", Agent: name}},
	})
	if err != nil {
		return nil, err
	}
	ro, err := yaml.Marshal(enrollRoleYAML{
		Name:          name,
		Description:   "Dedicated role for the enrolled agent " + name,
		Workflows:     []string{name},
		AllowedGroups: append([]string(nil), groups...),
	})
	if err != nil {
		return nil, err
	}
	ag, err := yaml.Marshal(enrollAgentYAML{
		Name:        name,
		Description: "Enrolled third-party agent (card version " + def.Provenance.CardVersion + "); spawn-only",
		Model:       def.Model,
		Tools:       def.Tools,
		Provenance:  def.Provenance,
	})
	if err != nil {
		return nil, err
	}
	return []enrollFile{
		{rel: "workflows/" + name + ".yaml", data: wf},
		{rel: "roles/" + name + ".yaml", data: ro},
		{rel: "agents/" + name + ".yaml", data: ag},
	}, nil
}

// enrollReload parses the exact bytes that will be written back into a
// config value (with its SourceFile set), so the validation sees what a
// later load of the written file will see. The bytes were just marshaled by
// enrollFiles, so a decode failure is a programming error.
func enrollReload[T any](data []byte, rel string) (T, error) {
	var v T
	if err := yaml.Unmarshal(data, &v); err != nil {
		return v, fmt.Errorf("reload %s: %w", rel, err)
	}
	switch p := any(&v).(type) {
	case *config.AgentDef:
		p.SourceFile = rel
	case *config.WorkflowDef:
		p.SourceFile = rel
	case *config.RoleDef:
		p.SourceFile = rel
	}
	return v, nil
}
