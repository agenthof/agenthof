package main

import (
	"io"
	"log/slog"

	"github.com/agenthof/agenthof/internal/apiclient"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/origin"
)

// configHost is serve.ConfigHost over this process's control root: the
// one apply (applyConfig), fed a bundle, with the server's bootstrap
// choice and the request's origin. The CLI's printed lines go to
// io.Discard; the outcome becomes the wire result.
type configHost struct {
	controlLog     string
	allowBootstrap bool
	logger         *slog.Logger
}

func (h *configHost) Apply(inv identity.Invoker, files map[string][]byte, pre apiclient.Precondition, via *engine.Origin) apiclient.ApplyResult {
	out := applyConfig(applyRequest{
		ControlLog:     h.controlLog,
		Invoker:        inv,
		Source:         bundleSource(files),
		Precondition:   &applyPrecondition{ExpectInstalled: pre.ExpectInstalled, ExpectNone: pre.ExpectNone},
		AllowBootstrap: h.allowBootstrap,
		Origin:         via,
	}, io.Discard)
	if out.Kind == applyLedgerDamaged {
		h.logger.Error("control ledger damaged; run: agenthof audit repair control --control-log " + h.controlLog)
	}
	return applyResult(out)
}

// applyResult maps an applyOutcome to the wire shape. The 500 bodies are
// fixed strings (the recorded reason can name store paths); the 422 lines
// are cleaned the way their recorded reason is.
func applyResult(o applyOutcome) apiclient.ApplyResult {
	res := apiclient.ApplyResult{ConfigHash: o.ConfigHash, Agents: o.Agents, Workflows: o.Workflows, Roles: o.Roles}
	if o.Head.Count > 0 {
		res.Head = &apiclient.Head{Hash: o.Head.Hash, Count: o.Head.Count}
	}
	if o.Reason != nil {
		res.Reason = o.Reason.Message
	}
	switch o.Kind {
	case applyInstalled:
		res.Status = apiclient.ApplyInstalled
		res.Bootstrap = !o.Installed
	case applyLedgerDamaged:
		res.Status = apiclient.ApplyLedgerDamaged
		res.Reason = apiclient.ReasonLedgerDamaged
	case applyBusy:
		res = apiclient.ApplyResult{Status: apiclient.ApplyBusy}
	case applyRefused:
		res.Status = apiclient.ApplyRefused
	case applyPreconditionFailed:
		res = apiclient.ApplyResult{Status: apiclient.ApplyPreconditionFailed, CurrentHash: o.CurrentHash}
	case applyRejected:
		res.Status = apiclient.ApplyRejected
		for _, e := range o.Errors {
			res.Errors = append(res.Errors, origin.Clean(e.Error()))
		}
	case applyError:
		res.Status = apiclient.ApplyError
		res.Reason = apiclient.ReasonStoreUnusable
	case applyAppendFailed:
		res = apiclient.ApplyResult{Status: apiclient.ApplyError, Reason: apiclient.ReasonNotRecorded}
	case applyInstalledNotRecorded:
		res.Status = apiclient.ApplyInstalledNotRecorded
	}
	return res
}
