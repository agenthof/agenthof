package broker

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestStaticEnvReturnsDirectBearer(t *testing.T) {
	t.Setenv("AGENTHOF_TEST_TOKEN", "s3cret-bearer")
	got, err := StaticEnv{}.Resolve(context.Background(), CredentialRef{
		Source: "static_env", Grant: "", TokenEnv: "AGENTHOF_TEST_TOKEN",
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "s3cret-bearer" {
		t.Fatalf("token = %q, want %q", got, "s3cret-bearer")
	}
}

func TestStaticEnvRejectsNonEmptyGrant(t *testing.T) {
	_, err := StaticEnv{}.Resolve(context.Background(), CredentialRef{
		Source: "static_env", Grant: "client_credentials", TokenEnv: "X",
	})
	if err == nil {
		t.Fatal("expected error for non-direct grant, got nil")
	}
}

func TestStaticEnvErrorNamesVarNotValue(t *testing.T) {
	_, err := StaticEnv{}.Resolve(context.Background(), CredentialRef{
		Source: "static_env", TokenEnv: "AGENTHOF_MISSING_VAR",
	})
	if err == nil {
		t.Fatal("expected error for missing var")
	}
	if got := err.Error(); !strings.Contains(got, "AGENTHOF_MISSING_VAR") {
		t.Fatalf("error %q should name the env var", got)
	}
}

// fakeBroker records which ref it saw and returns a fixed token.
type fakeBroker struct {
	last  CredentialRef
	token string
}

func (f *fakeBroker) Resolve(_ context.Context, ref CredentialRef) (string, error) {
	f.last = ref
	return f.token, nil
}

func TestDispatchRoutesOnGrant(t *testing.T) {
	static := &fakeBroker{token: "static-tok"}
	cc := &fakeBroker{token: "minted-tok"}
	te := &fakeBroker{token: "exchanged-tok"}
	d := Dispatch{StaticEnv: static, ClientCredentials: cc, TokenExchange: te}

	staticRef := CredentialRef{Grant: "", ResourceID: "static-resource"}
	got, err := d.Resolve(context.Background(), staticRef)
	if err != nil || got != "static-tok" {
		t.Fatalf("empty grant routed wrong: got %q err %v", got, err)
	}
	if static.last != staticRef {
		t.Fatalf("static broker got ref %+v, want %+v (ref must reach it unmodified)", static.last, staticRef)
	}
	if cc.last != (CredentialRef{}) || te.last != (CredentialRef{}) {
		t.Fatal("only the static broker should have been called so far")
	}

	ccGrantRef := CredentialRef{Grant: "client_credentials", ResourceID: "cc-resource"}
	got, err = d.Resolve(context.Background(), ccGrantRef)
	if err != nil || got != "minted-tok" {
		t.Fatalf("client_credentials routed wrong: got %q err %v", got, err)
	}
	if cc.last != ccGrantRef {
		t.Fatalf("client_credentials broker got ref %+v, want %+v (ref must reach it unmodified)", cc.last, ccGrantRef)
	}

	oboRef := CredentialRef{Grant: "token_exchange", ResourceID: "obo-resource", SubjectToken: "subj", Audience: "https://up"}
	got, err = d.Resolve(context.Background(), oboRef)
	if err != nil || got != "exchanged-tok" {
		t.Fatalf("token_exchange routed wrong: got %q err %v", got, err)
	}
	if te.last != oboRef {
		t.Fatalf("token_exchange broker got ref for resource %q grant %q, want it unmodified (subject token and audience included)", te.last.ResourceID, te.last.Grant)
	}
	if static.last != staticRef || cc.last != ccGrantRef {
		t.Fatal("other brokers' last refs changed unexpectedly")
	}

	if _, err := d.Resolve(context.Background(), CredentialRef{Grant: "device_code"}); err == nil {
		t.Fatal("unknown grant should error")
	}
}

// TestCredentialRefLogValueRedacts: a CredentialRef carries a subject-token
// VALUE (unlike every other field, which is a name), so it must render as
// REDACTED whenever it is passed to slog as an attribute value — as a bare
// value and via slog.Any.
func TestCredentialRefLogValueRedacts(t *testing.T) {
	const subject = "zq9subjecttokenAAAA1111"
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ref := CredentialRef{ResourceID: "github", Grant: "token_exchange", Audience: "https://up.example", SubjectToken: subject}
	logger.Debug("resolving", "ref", ref)
	logger.Debug("resolving", slog.Any("ref", ref))
	out := buf.String()
	if strings.Contains(out, subject) {
		t.Fatalf("subject token reached the log: %s", out)
	}
	if strings.Count(out, "REDACTED") != 2 {
		t.Fatalf("expected both log lines to render the ref as REDACTED:\n%s", out)
	}
}
