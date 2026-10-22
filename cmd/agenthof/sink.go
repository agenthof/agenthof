package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/agenthof/agenthof/internal/broker"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/control"
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
