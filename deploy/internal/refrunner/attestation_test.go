package refrunner

import (
	"reflect"
	"testing"
)

func TestMetaCarriesConfinerOnlyWhenSet(t *testing.T) {
	m := Attestation{Runtime: "refexec"}.Meta()
	if _, ok := m["confiner"]; ok {
		t.Fatal("empty confiner must be absent from the wire")
	}
	if _, ok := m["confiner_opts"]; ok {
		t.Fatal("empty confiner_opts must be absent")
	}
	m = Attestation{Runtime: "refexec", Confiner: "podman", ConfinerOpts: []string{"shared-host-scratch"}}.Meta()
	if m["confiner"] != "podman" || !reflect.DeepEqual(m["confiner_opts"], []string{"shared-host-scratch"}) {
		t.Fatal(m)
	}
}

func TestMetaHasExactlyTheWireKeys(t *testing.T) {
	a := Attestation{Runtime: "refexec", Session: "refexec-0a1b", Command: []string{"cat", "/work/x"}, PID: 4242, Spawn: 1, EnvNames: []string{}}
	got := a.Meta()
	want := map[string]any{
		"runtime": "refexec", "session": "refexec-0a1b", "command": []string{"cat", "/work/x"},
		"pid": 4242, "spawn": 1, "credential_env": "", "env_names": []string{}, "materialization": "",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Meta() = %#v\nwant   %#v", got, want)
	}
	if AttestationMetaKey != "agenthof.dev/runtime-attestation" {
		t.Fatalf("AttestationMetaKey = %q: the gateway reads exactly agenthof.dev/runtime-attestation", AttestationMetaKey)
	}
}
