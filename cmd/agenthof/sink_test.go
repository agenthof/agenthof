package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/broker"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/sink"
)

// TestSinkForDispatch: the floor is a nil interface (never a typed nil);
// s3-object-lock builds an *sink.S3 with the posture's retention; any other
// kind is "not implemented"; a URL without a bucket is the sink's own
// refusal.
func TestSinkForDispatch(t *testing.T) {
	be, err := sinkFor(config.Integrity{}, time.Minute)
	if err != nil || be != nil {
		t.Fatalf("floor: %v %#v", err, be)
	}
	cred := config.BackendCredential{CredentialSource: "static_env", ClientAuth: "sigv4", ClientIDEnv: "ID", ClientSecretEnv: "SECRET"}
	in := config.Integrity{Sink: "worm", SinkBackend: config.IntegrityBackend{Kind: "s3-object-lock", URL: "https://s3.eu-central-1.amazonaws.com/worm/agenthof/", Mode: "compliance", Retention: "7y", Credential: cred}}
	be, err = sinkFor(in, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	s3, ok := be.(*sink.S3)
	if !ok || s3.URL() != "https://s3.eu-central-1.amazonaws.com/worm/agenthof" || s3.Region() != "eu-central-1" {
		t.Fatalf("%T %v", be, be)
	}
	loc := s3.Locator("abc", 2, time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC))
	if loc.Key != "agenthof/abc/seg-000002" || loc.RetainUntil != time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC).Add(7*config.RetentionYear) {
		t.Fatalf("%+v", loc)
	}
	if _, err := sinkBackendFor(sinkSpec{Backend: config.IntegrityBackend{Kind: "gcs-bucket-lock", URL: "https://x.example/b", Retention: "1d"}}); err == nil || err.Error() != `sink backend kind "gcs-bucket-lock" is not implemented` {
		t.Fatalf("kind: %v", err)
	}
	if _, err := sinkBackendFor(sinkSpec{Backend: config.IntegrityBackend{Kind: "s3-object-lock", URL: "https://x.example", Retention: "1d", Credential: cred}}); err == nil || !strings.Contains(err.Error(), "names no bucket") {
		t.Fatalf("bucket: %v", err)
	}
	if _, err := sinkBackendFor(sinkSpec{Backend: config.IntegrityBackend{Kind: "s3-object-lock", URL: "https://x.example/b", Retention: "0d", Credential: cred}}); err == nil {
		t.Fatal("retention is parsed by the one grammar")
	}
}

// TestSinkCredentialRefAndKeys: the posture's credential maps onto the
// broker reference for the sink resource, and the resolver reads the env
// NAMES at call time — an unset name is an error naming it, never a value.
func TestSinkCredentialRefAndKeys(t *testing.T) {
	c := config.BackendCredential{CredentialSource: "static_env", ClientAuth: "sigv4", ClientIDEnv: "WORM_ID", ClientSecretEnv: "WORM_SECRET", TokenEnv: "WORM_SESSION"}
	want := broker.CredentialRef{ResourceID: "integrity/sink_backend", Source: "static_env", ClientAuth: "sigv4", ClientIDEnv: "WORM_ID", ClientSecretEnv: "WORM_SECRET", TokenEnv: "WORM_SESSION"}
	if got := sinkCredentialRef(c); got != want {
		t.Fatalf("%+v", got)
	}
	keys := sinkKeys(c)
	t.Setenv("WORM_ID", "AKID")
	t.Setenv("WORM_SECRET", "s3cr3t")
	t.Setenv("WORM_SESSION", "")
	_, err := keys(context.Background())
	if err == nil || !strings.Contains(err.Error(), "WORM_SESSION") || strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("unset session: %v", err)
	}
	t.Setenv("WORM_SESSION", "tok")
	kp, err := keys(context.Background())
	if err != nil || kp != (broker.KeyPair{ID: "AKID", Secret: "s3cr3t", Session: "tok"}) {
		t.Fatalf("%v %+v", err, kp)
	}
}

// TestProtectedLine pins the one line the seal prints for the copy.
func TestProtectedLine(t *testing.T) {
	until := time.Date(2033, 10, 20, 9, 0, 0, 0, time.UTC)
	res := control.SealResult{Sink: &control.SealSink{Kind: "s3-object-lock", URL: "https://s3.example/worm/agenthof", Key: "agenthof/abc/seg-000001", Mode: "compliance", RetainUntil: until.Add(-time.Hour)}, VersionID: "v-9", RetainUntil: until}
	if got := protectedLine(res); got != "protected: s3-object-lock https://s3.example/worm/agenthof key=agenthof/abc/seg-000001 version=v-9 compliance until 2033-10-20T09:00:00Z" {
		t.Fatal(got)
	}
	res.Existed = true
	if got := protectedLine(res); !strings.HasSuffix(got, " until 2033-10-20T09:00:00Z (already confirmed)") {
		t.Fatal(got)
	}
}
