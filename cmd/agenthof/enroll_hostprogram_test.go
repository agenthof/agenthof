package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// signedCardParams signs a card whose extension params are exactly params.
func signedCardParams(t *testing.T, kid string, priv ed25519.PrivateKey, params map[string]any) []byte {
	t.Helper()
	body := map[string]any{
		"name":    "Triage Bot",
		"version": "1.2.0",
		"capabilities": map[string]any{"extensions": []any{map[string]any{
			"uri":    "https://agenthof.dev/ext/agent/v1",
			"params": params,
		}}},
	}
	canon, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding
	ph, _ := json.Marshal(map[string]any{"alg": "EdDSA", "kid": kid})
	p := enc.EncodeToString(ph)
	sig := ed25519.Sign(priv, []byte(p+"."+enc.EncodeToString(canon)))
	body["signatures"] = []any{map[string]any{"protected": p, "signature": enc.EncodeToString(sig)}}
	out, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func hostProgramParams(extra map[string]any) map[string]any {
	p := map[string]any{
		"interface": "a2a",
		"model":     "fast",
		"host-program": map[string]any{
			"program": "acme-triage",
			"builds": []any{
				map[string]any{"os": "darwin", "arch": "arm64", "sha256": "sha256:" + strings.Repeat("c", 64)},
				map[string]any{"os": "linux", "arch": "amd64", "sha256": "sha256:" + strings.Repeat("d", 64)},
			},
		},
	}
	for k, v := range extra {
		p[k] = v
	}
	return p
}

func TestEnrollHostProgramOnlyCard(t *testing.T) {
	e := newEnrollEnv(t, true)
	if err := os.WriteFile(e.card, signedCardParams(t, "curator", e.priv, hostProgramParams(nil)), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := e.run(opsFlags...)
	if code != 0 {
		t.Fatalf("inspect: code=%d stderr=%s", code, stderr)
	}
	for _, want := range []string{
		"program:     acme-triage",
		"build darwin/arm64 sha256:" + strings.Repeat("c", 64),
		"build linux/amd64 sha256:" + strings.Repeat("d", 64),
		"program: acme-triage",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("disclosure lacks %q:\n%s", want, stdout)
		}
	}
	for _, bad := range []string{"artifact:", "image:"} {
		if strings.Contains(stdout, bad) {
			t.Errorf("a program-only card must not mention %q:\n%s", bad, stdout)
		}
	}

	code, stdout, stderr = e.run(append(opsFlags, "--accept", takeDigest(t, stdout))...)
	if code != 0 {
		t.Fatalf("accept: code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	for _, want := range []string{"seatbelt (program \"acme-triage\"", "linux/amd64 sha256:" + strings.Repeat("d", 64)} {
		if !strings.Contains(stdout, want) {
			t.Errorf("guidance lacks %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "podman") {
		t.Errorf("a program-only card gets no podman guidance:\n%s", stdout)
	}
	ev := e.last(t)
	if ev.Outcome != "success" || ev.Enroll == nil || ev.Enroll.Artifact != "" || ev.Enroll.HostProgram == nil ||
		ev.Enroll.HostProgram.Program != "acme-triage" || len(ev.Enroll.HostProgram.Builds) != 2 ||
		ev.Enroll.HostProgram.Builds[1].SHA256 != "sha256:"+strings.Repeat("d", 64) {
		t.Fatalf("success record = %+v", ev.Enroll)
	}
}

func TestEnrollBothFormsCard(t *testing.T) {
	e := newEnrollEnv(t, true)
	params := hostProgramParams(map[string]any{"artifact": e.art})
	if err := os.WriteFile(e.card, signedCardParams(t, "curator", e.priv, params), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := e.run(opsFlags...)
	if code != 0 {
		t.Fatalf("inspect: code=%d stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "artifact:    "+e.art) {
		t.Errorf("disclosure lacks the image:\n%s", stdout)
	}
	code, stdout, stderr = e.run(append(opsFlags, "--accept", takeDigest(t, stdout))...)
	if code != 0 {
		t.Fatalf("accept: code=%d stderr=%s", code, stderr)
	}
	for _, want := range []string{"podman (a digest-pinned image reference)", "seatbelt (program"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("guidance lacks %q:\n%s", want, stdout)
		}
	}
	if p := e.last(t).Enroll; p == nil || p.Artifact != e.art || p.HostProgram == nil {
		t.Fatalf("both forms must be recorded: %+v", p)
	}
}

func TestEnrollRefusesCardWithNoArtifactForm(t *testing.T) {
	e := newEnrollEnv(t, true)
	n := len(e.events(t))
	if err := os.WriteFile(e.card, signedCardParams(t, "curator", e.priv, map[string]any{"interface": "a2a"}), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := e.run(opsFlags...)
	if code != 1 || !strings.Contains(stderr, "artifact") || len(e.events(t)) != n {
		t.Fatalf("neither form: code=%d stderr=%s", code, stderr)
	}
}

func TestEnrollRefusesNonPrintableProgramID(t *testing.T) {
	e := newEnrollEnv(t, true)
	params := hostProgramParams(nil)
	params["host-program"].(map[string]any)["program"] = "acme\u202etriage"
	if err := os.WriteFile(e.card, signedCardParams(t, "curator", e.priv, params), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := e.run(opsFlags...)
	if code != 1 || !strings.Contains(stderr, "non-printable") || strings.Contains(stdout, "\u202e") {
		t.Fatalf("non-printable program id: code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}
