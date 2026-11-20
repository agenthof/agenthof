#!/usr/bin/env bash
# enroll-lib: what the enrollment-binding acceptance runs share — a throwaway
# card signer and the enroll steps — for scripts/e2e-refspawn-local.sh
# (hermetic), scripts/e2e-refspawn.sh (real rootless podman) and
# scripts/e2e-refspawn-seatbelt.sh (real macOS Seatbelt). Sourced, never run:
# it defines functions and nothing else — no options, no traps, no files.
# The helpers read the sourcing script's globals at CALL time: WORK (its
# scratch dir), its fail function and, for enroll_agent, ENROLL_ARGS (the
# --config/--control-log/--as/--groups arguments of every enroll) and
# AGENTHOF (the built binary, default $WORK/agenthof).

# enroll_build_signer: build $WORK/cardsign/cardsign. The signer writes a card
# in the shape the card verifier takes: a compact-sorted-keys body signed under
# an EdDSA protected header naming the signer's kid ("curator"). Usage:
#   cardsign KEYFILE OUT oci HEX         the OCI form, artifact ghcr.io/acme/echo@sha256:HEX
#   cardsign KEYFILE OUT host sha256:H   the host-program form, program acme-echo, this host's os/arch
# KEYFILE holds the Ed25519 seed; it is created on first use and reused after,
# so every card of one run is signed by the one trusted signer. The public key
# (base64) is printed.
enroll_build_signer() {
	mkdir -p "$WORK/cardsign"
	cat >"$WORK/cardsign/main.go" <<'GO'
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
)

func main() {
	keyFile, outFile, kind, value := os.Args[1], os.Args[2], os.Args[3], os.Args[4]
	var priv ed25519.PrivateKey
	if raw, err := os.ReadFile(keyFile); err == nil {
		seed, err := base64.StdEncoding.DecodeString(string(raw))
		if err != nil {
			panic(err)
		}
		priv = ed25519.NewKeyFromSeed(seed)
	} else {
		_, p, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		priv = p
		if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(p.Seed())), 0o600); err != nil {
			panic(err)
		}
	}
	pub := priv.Public().(ed25519.PublicKey)
	params := map[string]any{"interface": "a2a", "model": "fast"}
	switch kind {
	case "oci":
		params["artifact"] = "ghcr.io/acme/echo@sha256:" + value
	case "host":
		params["host-program"] = map[string]any{"program": "acme-echo", "builds": []any{
			map[string]any{"os": runtime.GOOS, "arch": runtime.GOARCH, "sha256": value},
		}}
	default:
		panic("unknown card kind " + kind)
	}
	body := map[string]any{
		"name":    "Enrolled Echo",
		"version": "1.0.0",
		"capabilities": map[string]any{"extensions": []any{map[string]any{
			"uri":    "https://agenthof.dev/ext/agent/v1",
			"params": params,
		}}},
	}
	enc := base64.RawURLEncoding
	canon, err := json.Marshal(body) // compact, sorted keys: already canonical for these values
	if err != nil {
		panic(err)
	}
	hdr, err := json.Marshal(map[string]any{"alg": "EdDSA", "kid": "curator"})
	if err != nil {
		panic(err)
	}
	p := enc.EncodeToString(hdr)
	sig := enc.EncodeToString(ed25519.Sign(priv, []byte(p+"."+enc.EncodeToString(canon))))
	body["signatures"] = []any{map[string]any{"protected": p, "signature": sig}}
	out, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(outFile, out, 0o644); err != nil {
		panic(err)
	}
	fmt.Print(base64.StdEncoding.EncodeToString(pub))
}
GO
	go build -o "$WORK/cardsign/cardsign" "$WORK/cardsign/main.go"
}

# enroll_card OUT KIND VALUE: sign a card (see enroll_build_signer) and print
# the signer's public key, base64 — the one a gateway lists in trusted_signers.
# Fails unless the card is non-empty and a key came back.
enroll_card() {
	local key
	key="$("$WORK/cardsign/cardsign" "$WORK/cardsign/key" "$1" "$2" "$3")" || fail "the card signer failed"
	{ [ -s "$1" ] && [ -n "$key" ]; } || fail "the signer produced no card or key"
	printf '%s' "$key"
}

# enroll_trust CONFIG KEY: make KEY the gateway's one trusted signer, and let
# the lead role enroll (the one control action enroll asks for).
enroll_trust() {
	printf 'trusted_signers:\n  - {kid: curator, key: %s}\n' "$2" >>"$1/gateway.yaml"
	sed -i.bak 's/^control: \[apply\]$/control: [apply, enroll]/' "$1/roles/lead.yaml" && rm -f "$1/roles/lead.yaml.bak"
	grep -qx 'control: \[apply, enroll\]' "$1/roles/lead.yaml" || fail "the lead role was not granted enroll"
}

# enroll_agent CARD NAME CONFIG: enroll CARD as agent NAME with the lead role
# in CONFIG (ENROLL_ARGS names CONFIG). Without --accept nothing is written and
# the digest is disclosed; then --accept that digest. Sets ENROLL_DIGEST and
# ENROLL_OUT (the accepted run's output).
enroll_agent() {
	local proposal
	proposal="$("${AGENTHOF:-$WORK/agenthof}" enroll "$1" --name "$2" --role lead "${ENROLL_ARGS[@]}")" || fail "enroll of $2 without --accept failed"
	ENROLL_DIGEST="$(printf '%s\n' "$proposal" | sed -n 's/^card digest: //p')"
	[ -n "$ENROLL_DIGEST" ] || { echo "$proposal"; fail "enroll of $2 disclosed no card digest"; }
	[ ! -e "$3/agents/$2.yaml" ] || fail "enroll of $2 wrote a file without --accept"
	ENROLL_OUT="$("${AGENTHOF:-$WORK/agenthof}" enroll "$1" --name "$2" --role lead "${ENROLL_ARGS[@]}" --accept "$ENROLL_DIGEST")" || fail "enroll --accept of $2 failed"
	printf '%s\n' "$ENROLL_OUT" | grep -q "enrolled \"$2\": 3 files created" || { echo "$ENROLL_OUT"; fail "enroll of $2 did not report three files"; }
}

# enroll_allow_spawn LEADFILE NAME: the operator's by-hand edit enroll's output
# asks for — the orchestrator may spawn the enrolled agent, and only by this
# edit. LEADFILE's may_spawn list must be its last block.
enroll_allow_spawn() {
	printf '  - role: %s\n    workflow: %s\n' "$2" "$2" >>"$1"
}

# ran_of LEDGER AGENT: "<kind> <value>..." the succeeded spawn event measured
# AGENT's compartment to run (child_artifact); nothing when none was recorded.
ran_of() {
	python3 - "$1" "$2" <<'PY'
import json, sys
for line in open(sys.argv[1]):
    if not line.strip():
        continue
    e = json.loads(line)
    if e.get("type") == "spawn" and e.get("status") == "succeeded":
        r = e.get("child_artifact", {}).get(sys.argv[2])
        if r:
            print(r["kind"], *r["values"])
PY
}
