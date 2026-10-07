package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/agenthof/agenthof/internal/apiclient"
	"github.com/agenthof/agenthof/internal/investigate"
)

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

// runViaServer is `run` over the API, printing exactly what the local
// path prints: the refusal line with the server's reason, or the finish
// line with the terminal status; exit 0 only on succeeded.
func runViaServer(base, token, role, workflow, input string, out io.Writer) int {
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

// investigateViaServer prints the server's investigate/1 document as-is
// (--json) or rendered as text, with the same exit code the local path
// derives.
func investigateViaServer(base, token string, q apiclient.InvestigateQuery, jsonOut bool, out io.Writer) int {
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
