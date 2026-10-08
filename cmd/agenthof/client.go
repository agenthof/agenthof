package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/agenthof/agenthof/internal/apiclient"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/investigate"
)

// loopbackHost reports whether host (no port) is loopback.
func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// warnInsecureServer warns when the bearer would travel in cleartext — a
// plain http:// base to a non-loopback host. The token is sent as a Bearer
// header, so that is a credential-in-the-clear risk; loopback and https are
// fine.
func warnInsecureServer(base string, w io.Writer) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "http" {
		return
	}
	if host := u.Hostname(); host != "" && !loopbackHost(host) {
		_, _ = fmt.Fprintln(w, "warning: --server uses plain HTTP to a non-loopback host; your token is sent in cleartext — use https")
	}
}

// serverBase resolves --server: the flag, else AGENTHOF_SERVER, else ""
// (the local path).
func serverBase(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return os.Getenv("AGENTHOF_SERVER")
}

// serverToken resolves the bearer for --server: --token, else
// AGENTHOF_TOKEN. The server verifies it; nothing is verified here.
func serverToken(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return os.Getenv("AGENTHOF_TOKEN")
}

// runViaServer is `run` over the API: the refusal line with the server's
// reason, or the finish line with the terminal status; exit 0 only on
// succeeded. It mirrors the local path closely but not byte-for-byte — an
// engine error shows as the terminal status rather than the raw error, and a
// 422's per-config-error lines are not echoed, because the server does not
// expose its own filesystem paths to a client.
func runViaServer(base, token, role, workflow, input string, out io.Writer) int {
	warnInsecureServer(base, os.Stderr)
	c := apiclient.New(base, token, nil)
	ctx := context.Background()
	acc, err := c.StartRun(ctx, apiclient.RunRequest{Role: role, Workflow: workflow, Input: input})
	if err != nil {
		_, _ = fmt.Fprintf(out, "run: %v\n", err)
		return 1
	}
	if acc.Status == apiclient.StatusRefused {
		_, _ = fmt.Fprintf(out, "run %s refused: %s\n", acc.RunID, acc.Reason)
		return 1
	}
	st, err := c.WaitRun(ctx, acc.RunID, 200*time.Millisecond)
	if err != nil {
		_, _ = fmt.Fprintf(out, "run %s error: %v\n", acc.RunID, err)
		return 1
	}
	_, _ = fmt.Fprintf(out, "run %s finished: %s\n", st.RunID, st.Status)
	if st.Status != "succeeded" {
		return 1
	}
	return 0
}

// auditViaServer prints the server-rendered audit — the same text the
// local command renders, config-join included — and exits as it would:
// 0 only when the ledger verified.
func auditViaServer(base, token, runID string, out io.Writer) int {
	warnInsecureServer(base, os.Stderr)
	text, integrity, err := apiclient.New(base, token, nil).Audit(context.Background(), runID)
	if err != nil {
		_, _ = fmt.Fprintf(out, "audit: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprint(out, text)
	if integrity != apiclient.IntegrityVerified {
		return 1
	}
	return 0
}

// applyViaServer is `apply` over the API: the bundle (from --bundle, or
// --config read by the configFiles enumeration), its local hash, one POST
// with the precondition, and the local path's lines — plus "installed:
// <hash>", which the operator needs for the next --if-installed. Exit 0
// only on installed; 1 for every other answer and every transport error.
func applyViaServer(base, token, cfgDir, bundlePath string, pre apiclient.Precondition, out io.Writer) int {
	warnInsecureServer(base, os.Stderr)
	files, err := loadBundle(cfgDir, bundlePath, os.Stdin)
	if err != nil {
		_, _ = fmt.Fprintf(out, "apply: %v\n", err)
		return 1
	}
	local, err := config.HashFiles(files)
	if err != nil {
		_, _ = fmt.Fprintf(out, "apply: %v\n", err)
		return 1
	}
	req := apiclient.ApplyRequest{Files: make(map[string]string, len(files))}
	for rel, data := range files {
		req.Files[rel] = string(data)
	}
	res, err := apiclient.New(base, token, nil).Apply(context.Background(), req, pre)
	if err != nil {
		_, _ = fmt.Fprintf(out, "apply: %v\n", err)
		return 1
	}
	return printApplyResult(res, pre, local, out)
}

// loadBundle builds the proposal: --bundle (a file, or "-" for stdin) is
// the request-body JSON, decoded to fail fast on garbage and to enforce the
// server's caps with the server's own words; otherwise --config is read by
// config.ReadBundle. Either way every value must be valid UTF-8 — a JSON
// string is UTF-8 by construction and encoding/json would silently replace
// bad bytes, so the raw bundle is checked before decoding and a config file
// is refused with its path.
func loadBundle(cfgDir, bundlePath string, stdin io.Reader) (map[string][]byte, error) {
	if bundlePath == "" {
		files, err := config.ReadBundle(cfgDir)
		if err != nil {
			return nil, err
		}
		for rel, data := range files {
			if !utf8.Valid(data) {
				return nil, fmt.Errorf("%s: not valid UTF-8; a bundle carries text", rel)
			}
		}
		return files, nil
	}
	var raw []byte
	var err error
	if bundlePath == "-" {
		raw, err = io.ReadAll(io.LimitReader(stdin, apiclient.MaxApplyBody+1))
	} else {
		raw, err = os.ReadFile(bundlePath)
	}
	if err != nil {
		return nil, err
	}
	if len(raw) > apiclient.MaxApplyBody {
		return nil, errors.New("bundle exceeds 1 MiB")
	}
	if !utf8.Valid(raw) {
		return nil, errors.New("bundle is not valid UTF-8")
	}
	var req apiclient.ApplyRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, fmt.Errorf("malformed bundle: %w", err)
	}
	if len(req.Files) == 0 {
		return nil, errors.New("files is required")
	}
	if len(req.Files) > apiclient.MaxBundleFiles {
		return nil, errors.New("too many files")
	}
	keys := make([]string, 0, len(req.Files))
	for rel := range req.Files {
		keys = append(keys, rel)
	}
	sort.Strings(keys)
	files := make(map[string][]byte, len(keys))
	for _, rel := range keys {
		if !config.ValidBundlePath(rel) {
			return nil, fmt.Errorf("invalid config path: %q", rel)
		}
		files[rel] = []byte(req.Files[rel])
	}
	return files, nil
}

// printApplyResult renders the server's answer as the local path prints
// its own, one row per status.
func printApplyResult(res apiclient.ApplyResult, pre apiclient.Precondition, localHash string, out io.Writer) int {
	head := func() {
		if res.Head != nil {
			_, _ = fmt.Fprintf(out, "control head: seq=%d sha256=%s\n", res.Head.Count, res.Head.Hash)
		}
	}
	switch res.Status {
	case apiclient.ApplyInstalled:
		_, _ = fmt.Fprintf(out, "registry ok: %d agents, %d workflows, %d roles\n", res.Agents, res.Workflows, res.Roles)
		head()
		_, _ = fmt.Fprintf(out, "installed: %s\n", res.ConfigHash)
		return 0
	case apiclient.ApplyRefused:
		_, _ = fmt.Fprintf(out, "apply: %s\n", res.Reason)
		head()
	case apiclient.ApplyPreconditionFailed:
		expected := pre.ExpectInstalled
		if pre.ExpectNone {
			expected = "none"
		}
		if res.CurrentHash == "" {
			_, _ = fmt.Fprintf(out, "apply: precondition failed: nothing is installed, not %s; retry with --if-installed none\n", expected)
			return 1
		}
		hint := ""
		if res.CurrentHash == localHash {
			hint = " — these bytes are already installed"
		}
		_, _ = fmt.Fprintf(out, "apply: precondition failed: installed configuration is %s, not %s; retry with --if-installed %s%s\n", res.CurrentHash, expected, res.CurrentHash, hint)
	case apiclient.ApplyRejected:
		for _, e := range res.Errors {
			_, _ = fmt.Fprintln(out, e)
		}
		head()
	case apiclient.ApplyBusy:
		_, _ = fmt.Fprintln(out, "apply: another apply is in progress; retry")
	case apiclient.ApplyError:
		_, _ = fmt.Fprintf(out, "apply: %s\n", res.Reason)
		head()
	case apiclient.ApplyLedgerDamaged:
		_, _ = fmt.Fprintln(out, "apply: control ledger damaged; an operator must run audit repair control on the server")
	case apiclient.ApplyInstalledNotRecorded:
		_, _ = fmt.Fprintf(out, "registry ok: %d agents, %d workflows, %d roles\n", res.Agents, res.Workflows, res.Roles)
		_, _ = fmt.Fprintln(out, msgInstalledNotRecorded)
	default:
		_, _ = fmt.Fprintf(out, "apply: server answered with an unknown status %q\n", res.Status)
	}
	return 1
}

// investigateViaServer prints the server's investigate/1 document as-is
// (--json) or rendered as text, with the same exit code the local path
// derives.
func investigateViaServer(base, token string, q apiclient.InvestigateQuery, jsonOut bool, out io.Writer) int {
	warnInsecureServer(base, os.Stderr)
	doc, err := apiclient.New(base, token, nil).Investigate(context.Background(), q)
	if err != nil {
		_, _ = fmt.Fprintf(out, "investigate: %v\n", err)
		return 1
	}
	// Decode first even for --json: the exit code comes from the document's
	// per-source integrity, and --json changes only the rendering.
	res, err := investigate.DecodeJSON(doc)
	if err != nil {
		_, _ = fmt.Fprintf(out, "investigate: %v\n", err)
		return 1
	}
	if jsonOut {
		_, _ = out.Write(doc)
	} else {
		_, _ = fmt.Fprint(out, investigate.RenderText(res))
	}
	return investigate.ExitCode(res)
}
