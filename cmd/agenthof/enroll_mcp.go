package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/agenthof/agenthof/internal/authz"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/ledger"
	"github.com/agenthof/agenthof/internal/origin"
	"github.com/agenthof/agenthof/internal/registry"
)

// enrollMCPAppend records the enroll_mcp event; a variable so a test can fail it.
var enrollMCPAppend = control.Append

// enrollMCPStdin is where --from-paste reads; a test replaces it.
var enrollMCPStdin io.Reader = os.Stdin

// maxPasteBytes bounds a pasted MCP configuration.
const maxPasteBytes = 1 << 20

const msgEnrollMCPDeclined = "the accepted digest does not match the proposed resource"

// splitList splits a comma-separated flag into trimmed, non-empty entries.
func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// mcpPaste is the standard MCP-server configuration shape.
type mcpPaste struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
}

// parsePaste reads a pasted MCP configuration: either the bare server object
// or the usual {"mcpServers": {"<name>": {...}}} wrapper holding exactly one
// server. It returns the launch argv and the env var NAMES only: every env
// VALUE is dropped here, so a pasted literal secret reaches neither the
// configuration nor the ledger (Article II).
func parsePaste(r io.Reader) (argv, envNames []string, err error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxPasteBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("read pasted configuration: %w", err)
	}
	if len(raw) > maxPasteBytes {
		return nil, nil, fmt.Errorf("pasted configuration is over the %d byte limit", maxPasteBytes)
	}
	var wrapped struct {
		MCPServers map[string]mcpPaste `json:"mcpServers"`
	}
	var p mcpPaste
	if err := json.Unmarshal(raw, &wrapped); err == nil && len(wrapped.MCPServers) > 0 {
		if len(wrapped.MCPServers) != 1 {
			return nil, nil, errors.New("the pasted configuration holds more than one server; paste exactly one")
		}
		for _, v := range wrapped.MCPServers {
			p = v
		}
	} else if err := json.Unmarshal(raw, &p); err != nil {
		return nil, nil, errors.New("the pasted configuration is not valid JSON of the form {command, args, env}")
	}
	if p.Command == "" {
		return nil, nil, errors.New("the pasted configuration has no command")
	}
	argv = append([]string{p.Command}, p.Args...)
	for n := range p.Env { // names only; the values are discarded
		envNames = append(envNames, n)
	}
	sort.Strings(envNames)
	return argv, envNames, nil
}

// mcpAcceptDigest is the digest the operator consents to: sha256 of the
// candidate resource marshaled alone, so it is reproducible from the
// disclosure and independent of the file it is later inserted into.
func mcpAcceptDigest(res config.ToolResource) (string, error) {
	b, err := yaml.Marshal(res)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// withMCPCandidate returns cfg plus the proposed resource (and grant), built
// in memory only, for validation before anything is written.
func withMCPCandidate(cfg config.Config, name string, res config.ToolResource, grantAgent string, grant config.ToolGrant) config.Config {
	out := cfg
	out.Gateway.Tools = map[string]config.ToolResource{}
	for k, v := range cfg.Gateway.Tools {
		out.Gateway.Tools[k] = v
	}
	out.Gateway.Tools[name] = res
	out.Agents = append([]config.AgentDef(nil), cfg.Agents...)
	if grantAgent != "" {
		for i := range out.Agents {
			if out.Agents[i].Name == grantAgent {
				out.Agents[i].Tools = append(append([]config.ToolGrant(nil), out.Agents[i].Tools...), grant)
			}
		}
	}
	return out
}

// fileSnapshot is a file's prior state, for rollback.
type fileSnapshot struct {
	path    string
	data    []byte
	existed bool
}

func snapshot(path string) (fileSnapshot, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return fileSnapshot{path: path}, nil
	}
	if err != nil {
		return fileSnapshot{}, err
	}
	return fileSnapshot{path: path, data: b, existed: true}, nil
}

// restore puts the file back as it was: an absent file is removed, an
// existing one is rewritten whole to a temp name and renamed into place.
func (s fileSnapshot) restore() error {
	if !s.existed {
		if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".enroll-restore-*")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(s.data)
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
		werr = os.Rename(tmp.Name(), s.path)
	}
	if werr != nil {
		_ = os.Remove(tmp.Name())
	}
	return werr
}

func fileSHA(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// cmdEnrollMCP is `enroll mcp <name>`: propose an operator-vetted local stdio
// MCP as a governed tool resource in the working configuration. Without
// --accept it only discloses what would be recorded and written. With
// --accept sha256:<digest> of the disclosed resource it validates the result,
// edits the working gateway.yaml (and, with --grant, one agent file) in place,
// and ledgers the enrollment. It installs nothing: apply is its own act.
func cmdEnrollMCP(argv []string, stdout, stderr io.Writer) int {
	name := ""
	if len(argv) > 0 && !strings.HasPrefix(argv[0], "-") {
		name, argv = argv[0], argv[1:]
	}
	fs := flag.NewFlagSet("enroll mcp", flag.ContinueOnError)
	nameFlag := fs.String("name", "", "name of the tool resource (or give it as the first argument)")
	command := fs.String("command", "", "launch argv, space-separated; the first element must be an absolute path to a pinned install")
	socket := fs.String("socket", "", "absolute path of the unix socket the bridge fronts the MCP on")
	tokenEnv := fs.String("token-env", "", "gateway-side bearer token env var NAME (required)")
	envNames := fs.String("env", "", "comma-separated env var NAMES to pass through to the MCP; never values")
	egress := fs.String("egress", "", "comma-separated hosts (host or host:port) the MCP may reach; empty means no network")
	tools := fs.String("tools", "", "comma-separated read-only tool allowlist (required)")
	grant := fs.String("grant", "", "agent to grant the read-only tools to; without it the resource is written but unreachable")
	fromPaste := fs.Bool("from-paste", false, "read a pasted MCP configuration ({command, args, env}) on stdin; env values are discarded")
	remote := fs.String("url", "", "remote MCP URL (not supported yet)")
	accept := fs.String("accept", "", "consent: proceed only if the proposed resource's digest is this sha256:<hex>, as disclosed by a run without --accept")
	cfgDir := fs.String("config", "./config", "working configuration directory edited in place")
	controlLog := fs.String("control-log", ".agenthof/control.jsonl", "control-plane ledger path; the installed configuration is read from installed/ beside it")
	as := fs.String("as", "", "invoker identity (defaults to the OS user); ignored when --token is given")
	groups := fs.String("groups", "", "comma-separated groups asserted for the --as identity; DEV ONLY — self-asserted, not verified, ignored when --token is given")
	token := fs.String("token", "", "raw OIDC token to authenticate the invoker (env AGENTHOF_TOKEN fallback); when set, identity comes from the token, not --as/--groups")
	fs.SetOutput(stderr)
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	if name == "" && *nameFlag != "" {
		name = *nameFlag
	} else if name == "" && fs.NArg() == 1 {
		name = fs.Arg(0)
	}
	usage := func(format string, a ...any) int {
		_, _ = fmt.Fprintf(stderr, "enroll mcp: "+format+"\n", a...)
		return 2
	}
	if *remote != "" {
		return usage("remote enrollment is not supported yet; enroll a local stdio MCP with --command or --from-paste")
	}
	const usageLine = "usage: agenthof enroll mcp <name> (--command <abs argv> | --from-paste) --socket <abs path> --token-env <NAME> --tools <a,b> [--env N,..] [--egress h,..] [--grant <agent>] [--accept sha256:<hex>]"
	if name == "" || (*command == "") == !*fromPaste || *socket == "" || *tokenEnv == "" || *tools == "" {
		if *tokenEnv == "" && name != "" {
			return usage("--token-env is required: the env var NAME the gateway reads the MCP's bearer token from\n%s", usageLine)
		}
		return usage("%s", usageLine)
	}
	if !registry.IsEnvName(*tokenEnv) {
		// The value is deliberately not echoed: it may be a pasted secret.
		return usage("--token-env must be an environment variable NAME, never a token value")
	}
	if !filepath.IsAbs(*socket) {
		return usage("--socket %q must be an absolute path", origin.Clean(*socket))
	}
	if fs.NArg() > 0 && (fs.NArg() != 1 || fs.Arg(0) != name) {
		return usage("unexpected argument %q", origin.Clean(fs.Arg(0)))
	}

	readOnly := splitList(*tools)
	if len(readOnly) == 0 || slices.Contains(readOnly, "*") {
		return usage("--tools must name the read-only tools explicitly; \"*\" is never written")
	}
	var acceptDigest string
	if *accept != "" {
		d, ok := parseAccept(*accept)
		if !ok {
			return usage("--accept must be sha256:<64 lowercase hex digits>")
		}
		acceptDigest = d
	}

	inv, assertedAs, refused, usageErr, verifyErr := resolveInvoker(*as, *groups, *token)
	if usageErr {
		_, _ = fmt.Fprintln(stderr, "enroll mcp: AGENTHOF_OIDC_ISSUER must be set in the environment to authenticate --token")
		return 2
	}
	if !controlLedgerWritable("enroll mcp", *controlLog, stderr) {
		return 1
	}
	record := func(outcome string, reason *control.Reason, p *control.EnrollMCP, code int) int {
		head, err := enrollMCPAppend(*controlLog, control.Event{
			Action:     "enroll_mcp",
			Outcome:    outcome,
			Reason:     reason,
			Invoker:    inv,
			AssertedAs: assertedAs,
			Witness:    control.CaptureWitness(),
			EnrollMCP:  p,
		})
		if err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "control head: seq=%d sha256=%s\n", head.Count, head.Hash)
		return code
	}
	if refused {
		_, _ = fmt.Fprintf(stderr, "enroll mcp: token authentication failed: %v\n", verifyErr)
		return record("refused", &control.Reason{Code: control.CodeTokenVerificationFailed, Message: "token verification failed"}, nil, 1)
	}

	store := installedStore(*controlLog)
	unlock, lockErr := ledger.LockFileShared(installedLock(*controlLog))
	if lockErr != nil {
		if errors.Is(lockErr, ledger.ErrLockHeld) {
			return mcpRefusal(stderr, "%s", msgLockBusy)
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
		_, _ = fmt.Fprintf(stderr, "enroll mcp: %s\n", msgNothingInstalled)
		_, _ = fmt.Fprintf(stderr, "%s under %s; run: agenthof apply --config <dir> --control-log %s\n", msgNoConfigInstalled, store, *controlLog)
		return record("refused", &control.Reason{Code: control.CodeNotAuthorized, Message: msgNothingInstalled}, nil, 1)
	}
	if refusal != nil {
		switch {
		case refusal.Transient():
			return mcpRefusal(stderr, "%s", msgLockBusy)
		case refusal.Kind != verifyNotOnRecord:
			return mcpRefusal(stderr, "%s", refusal.Error())
		}
		_, _ = fmt.Fprintf(stderr, "enroll mcp: %s\n", refusal.Error())
		return record("refused", vouchRefused(refusal), nil, 1)
	}
	if !authz.ControlAllows(instCfg.Roles, inv, "enroll") {
		reason := control.NotAuthorized("enroll")
		_, _ = fmt.Fprintf(stderr, "enroll mcp: %s\n", reason.Message)
		return record("refused", reason, nil, 1)
	}

	grantDef := config.ToolGrant{Resource: name, Tools: readOnly, Mode: "read-only"}
	// loadWork loads the working configuration afresh, refuses a name already
	// in use (in it or the installed one) and resolves the --grant agent's
	// file. It is run once to decide and again under the lock before writing,
	// so the write is judged against the files as they are then.
	loadWork := func() (workCfg config.Config, grantPath string, code int) {
		workCfg, loadErrs := config.LoadDir(*cfgDir)
		if len(loadErrs) > 0 {
			for _, e := range loadErrs {
				_, _ = fmt.Fprintln(stderr, origin.Clean(e.Error()))
			}
			return workCfg, "", mcpRefusal(stderr, "the configuration in %s does not load; fix it before enrolling", *cfgDir)
		}
		if err := checkEnrollName(name, workCfg, instCfg); err != nil {
			return workCfg, "", mcpRefusal(stderr, "%v", err)
		}
		for _, cfg := range []config.Config{workCfg, instCfg} {
			for id := range cfg.Gateway.Tools {
				if strings.EqualFold(id, name) {
					return workCfg, "", mcpRefusal(stderr, "name %q is already a tool resource in the configuration", name)
				}
			}
		}
		if *grant != "" {
			for i := range workCfg.Agents {
				if workCfg.Agents[i].Name == *grant {
					grantPath = workCfg.Agents[i].SourceFile
				}
			}
			if grantPath == "" {
				return workCfg, "", mcpRefusal(stderr, "--grant %q is not an agent in %s", origin.Clean(*grant), *cfgDir)
			}
		}
		return workCfg, grantPath, 0
	}
	workCfg, _, code := loadWork()
	if code != 0 {
		return code
	}

	// Resolve the launch source. Env VALUES never leave parsePaste.
	var cmdArgv, envList []string
	if *fromPaste {
		a, e, err := parsePaste(enrollMCPStdin)
		if err != nil {
			return usage("%v", err)
		}
		cmdArgv, envList = a, e
	} else {
		cmdArgv = strings.Fields(*command)
	}
	for _, n := range splitList(*envNames) {
		if !slices.Contains(envList, n) {
			envList = append(envList, n)
		}
	}
	sort.Strings(envList)
	if len(cmdArgv) == 0 || !filepath.IsAbs(cmdArgv[0]) {
		return usage("the command must start with an absolute path to a pinned install")
	}
	if registry.IsFetchAtSpawn(cmdArgv) {
		return usage("the command must be a pinned install, not fetch-at-spawn (npx, npm, uvx, pipx, bunx); nothing written")
	}
	res := config.ToolResource{
		Kind:             "mcp",
		Runtime:          "refbridge",
		URL:              "unix://" + *socket,
		CredentialSource: "static_env",
		TokenEnv:         *tokenEnv,
		Command:          cmdArgv,
		EnvPassthrough:   envList,
		Egress:           splitList(*egress),
		ReadOnlyTools:    readOnly,
	}
	digest, err := mcpAcceptDigest(res)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "enroll mcp: %v\n", err)
		return 1
	}
	payload := &control.EnrollMCP{Resource: name, Command: cmdArgv, EnvNames: envList, ReadOnlyTools: readOnly}
	// The ledger's bounds are checked now, not at Append, so an over-bound
	// enrollment is refused before it is disclosed, digested or written.
	if err := control.ValidateEnrollMCP(payload); err != nil {
		return mcpRefusal(stderr, "%v; nothing written", err)
	}

	// validate runs the registry's own validation over the configuration plus
	// the proposal, in memory: nothing is written unless it passes.
	validate := func(cfg config.Config) int {
		cand := withMCPCandidate(cfg, name, res, *grant, grantDef)
		if _, verrs := registry.Build(cand); len(verrs) > 0 {
			for _, e := range verrs {
				_, _ = fmt.Fprintln(stderr, origin.Clean(e.Error()))
			}
			return mcpRefusal(stderr, "the enrolled resource would not pass validation in %s; nothing was written", *cfgDir)
		}
		return 0
	}
	if code := validate(workCfg); code != 0 {
		return code
	}

	// Disclose: exactly what the ledger will hold and what is written.
	resYAML, _ := yaml.Marshal(res)
	_, _ = fmt.Fprintf(stdout, "enroll mcp: proposed governed MCP resource %q\n", name)
	_, _ = fmt.Fprintf(stdout, "command (recorded verbatim in the ledger): %q\n", cmdArgv)
	_, _ = fmt.Fprintf(stdout, "env names (passed through; values are never read or recorded): %s\n", strings.Join(envList, ", "))
	if *fromPaste && len(envList) > 0 {
		_, _ = fmt.Fprintln(stdout, "note: any env values in the pasted configuration were discarded; set them in the environment the MCP runs in")
	}
	_, _ = fmt.Fprintf(stdout, "egress: %s\n", egressLabel(res.Egress))
	_, _ = fmt.Fprintf(stdout, "read-only tools: %s\n", strings.Join(readOnly, ", "))
	if *grant != "" {
		_, _ = fmt.Fprintf(stdout, "grant: agent %q gets exactly those tools, read-only\n", *grant)
	} else {
		_, _ = fmt.Fprintln(stdout, "grant: none; the resource is inert (unreachable) until an agent is granted it")
	}
	_, _ = fmt.Fprintf(stdout, "resource, as it will be written to gateway.yaml:\n%s", resYAML)
	_, _ = fmt.Fprintf(stdout, "accept-digest: sha256:%s\n", digest)
	if *accept == "" {
		_, _ = fmt.Fprintf(stdout, "nothing written. To enroll this resource body, run again with: --accept sha256:%s\n(the digest binds the resource body above, not the name or the --grant target; check those too)\n", digest)
		return 0
	}

	if err := checkAccept("sha256:"+acceptDigest, digest); err != nil {
		_, _ = fmt.Fprintf(stderr, "enroll mcp: %s; nothing written\n", msgEnrollMCPDeclined)
		return record("refused", &control.Reason{Code: control.CodeConsentDeclined, Message: msgEnrollMCPDeclined}, nil, 1)
	}

	// Write, under the installed-configuration lock, and only if the
	// installed configuration is still the one this decision was made against.
	wunlock, lockErr := ledger.LockFile(installedLock(*controlLog))
	if lockErr != nil {
		if errors.Is(lockErr, ledger.ErrLockHeld) {
			return mcpRefusal(stderr, "%s", msgLockBusy)
		}
		return mcpRefusal(stderr, "%v", lockErr)
	}
	defer wunlock()
	if cur, ok, err := config.InstalledHash(store); err != nil || !ok || cur != hash {
		return mcpRefusal(stderr, "the installed configuration changed while enrolling; nothing written; run again")
	}

	// Reload under the lock and judge the write against the files as they are
	// now; the agent file path comes from this load too.
	freshCfg, grantPath, code := loadWork()
	if code != 0 {
		return code
	}
	if code := validate(freshCfg); code != 0 {
		return code
	}
	gwPath := filepath.Join(*cfgDir, "gateway.yaml")
	snaps := []fileSnapshot{}
	// fail reverts every edit made so far and refuses. It claims the edits
	// were reverted only if every restore succeeded; otherwise it names the
	// files that need the operator's attention.
	fail := func(cause string, a ...any) int {
		var stuck []string
		for _, s := range snaps {
			if err := s.restore(); err != nil {
				stuck = append(stuck, s.path)
			}
		}
		msg := fmt.Sprintf(cause, a...)
		if len(stuck) > 0 {
			return mcpRefusal(stderr, "%s; the edits could NOT be fully reverted: check %s by hand", msg, strings.Join(stuck, ", "))
		}
		return mcpRefusal(stderr, "%s; the edits were reverted", msg)
	}
	gwSnap, err := snapshot(gwPath)
	if err != nil {
		return mcpRefusal(stderr, "%v; nothing written", err)
	}
	snaps = append(snaps, gwSnap)
	files := []string{"gateway.yaml"}
	if err := config.InsertToolResource(gwPath, name, res); err != nil {
		return fail("%v", err)
	}
	if *grant != "" {
		agentPath := filepath.Join(*cfgDir, filepath.FromSlash(grantPath))
		asnap, err := snapshot(agentPath)
		if err != nil {
			return fail("%v", err)
		}
		snaps = append(snaps, asnap)
		if err := config.InsertGrant(agentPath, grantDef); err != nil {
			return fail("%v", err)
		}
		files = append(files, filepath.ToSlash(grantPath))
	}
	// Confirm the written state validates before ledgering it, so a recorded
	// success always describes a validated, written configuration.
	wroteCfg, reloadErrs := config.LoadDir(*cfgDir)
	if len(reloadErrs) > 0 {
		return fail("the written configuration does not load: %s", origin.Clean(reloadErrs[0].Error()))
	}
	if _, verrs := registry.Build(wroteCfg); len(verrs) > 0 {
		return fail("the written configuration does not validate: %s", origin.Clean(verrs[0].Error()))
	}
	var written []control.EnrollFile
	for _, rel := range files {
		sum, err := fileSHA(filepath.Join(*cfgDir, filepath.FromSlash(rel)))
		if err != nil {
			return fail("%v", err)
		}
		written = append(written, control.EnrollFile{Path: rel, SHA256: sum})
	}
	payload.Files = written
	head, err := enrollMCPAppend(*controlLog, control.Event{
		Action:     "enroll_mcp",
		Outcome:    "success",
		Invoker:    inv,
		AssertedAs: assertedAs,
		Witness:    control.CaptureWitness(),
		EnrollMCP:  payload,
	})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return fail("the enrollment could not be recorded")
	}
	_, _ = fmt.Fprintf(stdout, "enrolled %q: %d file(s) edited under %s\n", name, len(files), *cfgDir)
	_, _ = fmt.Fprintf(stdout, "control head: seq=%d sha256=%s\n", head.Count, head.Hash)
	if *grant == "" {
		_, _ = fmt.Fprintf(stdout, "the resource %q is inert: no agent is granted it, so it is unreachable until one is\n", name)
	}
	_, _ = fmt.Fprintf(stdout, "next: agenthof apply --config %s\n", *cfgDir)
	return 0
}

// mcpRefusal prints a refusal on the enroll mcp channel and returns 1.
func mcpRefusal(w io.Writer, format string, a ...any) int {
	_, _ = fmt.Fprintf(w, "enroll mcp: "+format+"\n", a...)
	return 1
}

func egressLabel(e []string) string {
	if len(e) == 0 {
		return "none (the compartment runs with no network)"
	}
	return strings.Join(e, ", ")
}
