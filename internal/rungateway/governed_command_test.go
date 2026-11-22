package rungateway

import (
	"testing"

	"github.com/agenthof/agenthof/internal/config"
)

func governedResource(url string, command []string) config.ToolResource {
	r := resource(url, "refbridge")
	r.Command = command
	return r
}

func TestGovernedCommandMatchingAttestationSucceeds(t *testing.T) {
	ts := newAttestingUpstream(t, goodAttestation(), false)
	result, events, err := runOneCall(t, governedResource(ts.URL, []string{"/stdio-tool", "-credential-env", "DEMO_TOKEN"}))
	if err != nil || result.IsError {
		t.Fatalf("call failed: %v %+v", err, result)
	}
	if e := onlyToolCall(t, events); e.Status != "succeeded" || e.RuntimeAttestation == nil {
		t.Fatalf("event = %+v", e)
	}
}

func TestGovernedCommandMismatchFailsCall(t *testing.T) {
	for name, declared := range map[string][]string{
		"different exe":   {"/other-tool", "-credential-env", "DEMO_TOKEN"},
		"extra argument":  {"/stdio-tool", "-credential-env", "DEMO_TOKEN", "-x"},
		"shorter argv":    {"/stdio-tool"},
		"different order": {"-credential-env", "DEMO_TOKEN", "/stdio-tool"},
	} {
		t.Run(name, func(t *testing.T) {
			ts := newAttestingUpstream(t, goodAttestation(), false)
			result, events, err := runOneCall(t, governedResource(ts.URL, declared))
			const reason = "runtime attestation command does not match the governed launch spec"
			if err != nil || !result.IsError || resultErrorText(result) != reason {
				t.Fatalf("agent must get an error result with the fixed reason, got %v %+v", err, result)
			}
			if e := onlyToolCall(t, events); e.Status != "failed" || e.Reason != reason {
				t.Fatalf("event = %+v", e)
			}
		})
	}
}

func TestNoDeclaredCommandSkipsTheCommandCheck(t *testing.T) {
	ts := newAttestingUpstream(t, goodAttestation(), false)
	result, events, err := runOneCall(t, resource(ts.URL, "refbridge"))
	if err != nil || result.IsError {
		t.Fatalf("a legacy resource with no command must be unchanged: %v %+v", err, result)
	}
	if e := onlyToolCall(t, events); e.Status != "succeeded" {
		t.Fatalf("event = %+v", e)
	}
}

func TestGovernedCommandWithMissingAttestationKeepsMissingReason(t *testing.T) {
	ts := newAttestingUpstream(t, nil, false)
	result, events, err := runOneCall(t, governedResource(ts.URL, []string{"/stdio-tool"}))
	if err != nil || !result.IsError || resultErrorText(result) != "runtime attestation missing" {
		t.Fatalf("got %v %+v", err, result)
	}
	if e := onlyToolCall(t, events); e.Status != "failed" || e.Reason != "runtime attestation missing" {
		t.Fatalf("event = %+v", e)
	}
}
