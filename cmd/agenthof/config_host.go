package main

import (
	"errors"
	"io"
	"log/slog"

	"github.com/agenthof/agenthof/internal/apiclient"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/origin"
	"github.com/agenthof/agenthof/internal/serve"
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
	if out.Kind == applyInstalledNotSigned {
		// The cause can name paths: logged here for the operator, never returned.
		h.logger.Warn(msgInstalledNotSigned+"; "+signRemedy(h.controlLog, out.SignCause), "config_hash", out.ConfigHash, "err", out.SignCause)
	}
	return applyResult(out)
}

// applyResult maps an applyOutcome to the wire shape, carrying the signing
// key id on an installed result. The 500 bodies are
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
		res.KeyID = o.KeyID
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
	case applyInstalledNotSigned:
		res.Status = apiclient.ApplyInstalledNotSigned
	}
	return res
}

// Pull is serve.ConfigHost's read: the one pull (pullConfig) on the API
// path, authorized against the installed roles. The cause of a store, ledger
// or bundle failure can name store paths, so it is logged here, where the
// operator who has the host reads it, and never returned to a client — the
// same rule applyResult applies to a 500. A not-signed verdict is logged at
// Warn with the config sign remedy, or at Info with none when the read
// merely raced an install.
func (h *configHost) Pull(inv identity.Invoker) serve.PullResult {
	out := pullConfig(pullRequest{ControlLog: h.controlLog, Authorize: true, Invoker: inv})
	status := pullStatus(out.Kind)
	switch out.Kind {
	case pullStoreUnusable, pullNotBundleable:
		h.logger.Error("config pull failed", "status", status, "err", out.Err)
	case pullLedgerDamaged:
		h.logger.Error("config pull failed", "status", status, "err", out.Err)
		h.logger.Error("control ledger damaged; run: agenthof audit repair control --control-log " + h.controlLog)
	case pullNotSigned:
		if errors.Is(out.Err, errSignatureNewer) {
			// This read raced an install; a retry gets 200. No remedy — a
			// config sign hint here would be false.
			h.logger.Info("config pull not signed", "status", status, "err", out.Err)
		} else {
			h.logger.Warn("config pull not signed; run: agenthof config sign --control-log "+h.controlLog, "status", status, "err", out.Err)
		}
	}
	return serve.PullResult{Status: status, Snapshot: out.Snapshot}
}

// pullStatus maps a pull outcome to its wire status. An unknown kind falls
// through to store_unusable, the fail-closed answer.
func pullStatus(k pullKind) string {
	switch k {
	case pulled:
		return serve.PullOK
	case pullNothingInstalled:
		return serve.PullNothingInstalled
	case pullRefused:
		return serve.PullRefused
	case pullNotBundleable:
		return serve.PullNotBundleable
	case pullLedgerDamaged:
		return serve.PullLedgerDamaged
	case pullBusy:
		return serve.PullBusy
	case pullNotRecorded:
		return serve.PullNotRecorded
	case pullNotSigned:
		return serve.PullNotSigned
	}
	return serve.PullStoreUnusable
}
