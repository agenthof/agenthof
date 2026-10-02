#!/usr/bin/env bash
# e2e-refexec-local: prove the REAL agenthof binary serves the exec door
# first-hand over a Unix socket, with no container runtime. The runtime is a
# stand-in built from refexec's own test tree: the real refexec program with
# a fake podman in place of podman, so each "compartment" is the command run
# directly on the host — the door, the ledger and audit are real. Asserts:
# an allowlisted command runs, its output is the step artifact, the ledger
# records the exec with mode runtime and refexec's first-hand attestation
# (argv, pid, session, injected environment NAMES — an unlisted variable is
# never injected nor named), audit renders it on succeeded and failed lines,
# the exec event never carries the output body; an off-allowlist command is
# refused before the runtime is asked; /exec/run is refused on an agent that
# declares no exec (the retired agent-asserted routes' recorded refusal is now
# covered by the in-process rungateway tests, not this script); a
# runtime that attests a different command, a missing runtime, a runtime in
# a non-private socket directory and a runtime that outlives the deadline
# each record a failed exec and fail the step; the deadline removes the
# compartment; and config is law at apply and at the runtime. Requires go
# and python3. Runs on macOS and Linux.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Short on purpose: Unix socket paths have a small OS length limit. The
# runtime's directory is SEPARATE from the gateway socket dir and mode 0700,
# as refexec and Agenthof both require; OPEN_DIR is deliberately 0755.
SOCK_DIR="$(mktemp -d /tmp/rx.XXXXXX)"
EXEC_DIR="$(mktemp -d /tmp/rx.XXXXXX)"
OPEN_DIR="$(mktemp -d /tmp/rx.XXXXXX)"
chmod 0700 "$EXEC_DIR"
chmod 0755 "$OPEN_DIR"
WORK="$(mktemp -d /tmp/rx.XXXXXX)"
WS="$WORK/workspace"
mkdir -p "$WS"
PIDS=()
cleanup() {
	for p in ${PIDS[@]+"${PIDS[@]}"}; do
		kill "$p" >/dev/null 2>&1 || true
		wait "$p" >/dev/null 2>&1 || true
	done
	rm -rf "$SOCK_DIR" "$EXEC_DIR" "$OPEN_DIR" "$WORK"
}
trap cleanup EXIT
unset AGENTHOF_TOKEN || true

fail() {
	echo "e2e-refexec-local: FAIL — $*"
	exit 1
}
sha_stdin() { python3 -c 'import hashlib, sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())'; }
# no_leak VALUE WHAT: VALUE must appear in no ledger, artifact, process log,
# or captured agenthof output. Never prints VALUE.
no_leak() {
	if grep -rqF -- "$1" "$WORK/logs" "$WORK/artifacts" "$WORK"/*.err 2>/dev/null; then
		fail "$2 reached the ledger, an artifact, or a process log"
	fi
	if printf '%s\n' "${OUTS[@]}" | grep -qF -- "$1"; then
		fail "$2 reached agenthof's output"
	fi
}
command -v pgrep >/dev/null 2>&1 || fail "pgrep is required to prove a cancelled command is gone"

go build -o "$WORK/agenthof" ./cmd/agenthof
go build -o "$WORK/echo-agent" ./examples/echo-agent
go test -c -o "$WORK/refexec-stub" ./deploy/refexec

NONCE="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
OUTS=()

# --- the runtime's config (the fake podman ignores image, volume and limits)
exec_config() { # $1 = socket path, $2 = "no-timeout" to omit the timeout
	cat <<EOF
socket: $1
image: example.test/exec:1
workspace:
  volume: e2e-work
  path: /work
limits:
  memory: 256m
  cpus: "1"
  pids: 64
compartments:
  max: 2
env_allow: ["REFEXEC_E2E_MARKER"]
EOF
	[ "${2:-}" = no-timeout ] || echo "timeout: 30s"
}
exec_config "$EXEC_DIR/exec.sock" >"$WORK/refexec.yaml"
exec_config "$EXEC_DIR/forged.sock" >"$WORK/refexec-forged.yaml"

# Config is law: a runtime config without a timeout is refused.
exec_config "$EXEC_DIR/bad.sock" no-timeout >"$WORK/refexec-bad.yaml"
if "$WORK/refexec-stub" -refexec-test-stub -config "$WORK/refexec-bad.yaml" >/dev/null 2>"$WORK/check.err"; then
	fail "a refexec config without a timeout was accepted"
fi
grep -q "timeout is required" "$WORK/check.err" || fail "the refusal did not name timeout"

# REFEXEC_E2E_MARKER is allowlisted and must reach the command; LEAKED_SECRET
# is not and must never be injected nor named.
REFEXEC_E2E_MARKER=1 LEAKED_SECRET="not-for-the-command-$NONCE" "$WORK/refexec-stub" -refexec-test-stub -config "$WORK/refexec.yaml" 2>"$WORK/refexec.err" &
PIDS+=($!)
REFEXEC_E2E_MARKER=1 "$WORK/refexec-stub" -refexec-test-stub -config "$WORK/refexec-forged.yaml" -misattest 2>"$WORK/refexec-forged.err" &
PIDS+=($!)
"$WORK/echo-agent" -socket "$SOCK_DIR/agent.sock" -workspace "$WS" 2>"$WORK/agent.err" &
PIDS+=($!)
for i in $(seq 1 60); do
	[ -S "$EXEC_DIR/exec.sock" ] && [ -S "$EXEC_DIR/forged.sock" ] && [ -S "$SOCK_DIR/agent.sock" ] && break
	[ "$i" = 60 ] && { cat "$WORK"/*.err || true; fail "sockets never appeared"; }
	sleep 0.5
done
[ "$(python3 -c 'import os, sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o777))' "$EXEC_DIR/exec.sock")" = "0o600" ] || fail "runtime socket is not mode 0600"

# --- a hermetic Agenthof config, written from scratch
mkdir -p "$WORK/config/agents" "$WORK/config/workflows" "$WORK/config/roles"
cat >"$WORK/config/gateway.yaml" <<EOF
refbox_socket_dir: $SOCK_DIR
models:
  fast:
    endpoint: http://127.0.0.1:9/v1
    model: fast
    api_key_env: AGENTHOF_GATEWAY_KEY
defaults:
  model: fast
EOF
agent() { # $1 = name, $2 = exec block (indented two spaces), or "" for no exec
	{
		cat <<EOF
name: $1
description: e2e agent $1
model: fast
instruction: Run the script.
output: output
execution: fronted
endpoint: unix://$SOCK_DIR/agent.sock
EOF
		[ -z "$2" ] || printf 'exec:\n%s\n' "$2"
	} >"$WORK/config/agents/$1.yaml"
	cat >"$WORK/config/workflows/$1.yaml" <<EOF
name: $1
description: one step through $1
steps:
  - name: run
    agent: $1
EOF
}
agent exec-runner "  runtime: refexec
  url: unix://$EXEC_DIR/exec.sock
  timeout: 30s
  allow:
    - exe: env
    - exe: false
    - exe: sleep"
agent exec-slow "  runtime: refexec
  url: unix://$EXEC_DIR/exec.sock
  timeout: 1s
  allow:
    - exe: sleep"
agent exec-forged "  runtime: refexec
  url: unix://$EXEC_DIR/forged.sock
  timeout: 30s
  allow:
    - exe: env"
agent exec-missing "  runtime: refexec
  url: unix://$EXEC_DIR/missing.sock
  timeout: 30s
  allow:
    - exe: env"
agent exec-open "  runtime: refexec
  url: unix://$OPEN_DIR/exec.sock
  timeout: 30s
  allow:
    - exe: env"
agent exec-none ""
cat >"$WORK/config/roles/exec-operator.yaml" <<EOF
name: exec-operator
description: Runs the refexec e2e workflows
workflows: [exec-runner, exec-slow, exec-forged, exec-missing, exec-open, exec-none]
allowed_groups: ["exec-users"]
EOF
export AGENTHOF_GATEWAY_KEY="host-side-dummy-key-$NONCE"   # the model route is never called; the key only lets it resolve

"$WORK/agenthof" apply --config "$WORK/config" --control-log "$WORK/control.jsonl" --as ci --groups exec-users

# Config is law at apply too: an exec block without a url is rejected for
# the missing field; the retired mode key is rejected by name — on a
# first-hand shape and on the old agent-reported shape alike.
reject_apply() { # $1 = agent yaml body, $2 = expected message fragment
	rm -rf "$WORK/badcfg" && mkdir -p "$WORK/badcfg" && cp -R "$WORK/config/." "$WORK/badcfg/"
	printf '%s\n' "$1" >"$WORK/badcfg/agents/exec-runner.yaml"
	if "$WORK/agenthof" apply --config "$WORK/badcfg" --control-log "$WORK/control.jsonl" --as ci --groups exec-users >"$WORK/apply-bad.out" 2>&1; then
		fail "apply accepted: $2"
	fi
	grep -q "$2" "$WORK/apply-bad.out" || { cat "$WORK/apply-bad.out"; fail "apply did not say: $2"; }
}
reject_apply "name: exec-runner
execution: fronted
endpoint: unix://$SOCK_DIR/agent.sock
model: fast
instruction: x
output: output
exec:
  runtime: refexec
  timeout: 30s
  allow:
    - exe: env" "exec.url must be a unix:// socket path"
reject_apply "name: exec-runner
execution: fronted
endpoint: unix://$SOCK_DIR/agent.sock
model: fast
instruction: x
output: output
exec:
  mode: runtime
  runtime: refexec
  url: unix://$EXEC_DIR/exec.sock
  timeout: 30s
  allow:
    - exe: env" "exec.mode is no longer supported; exec is always first-hand via a runtime"
reject_apply "name: exec-runner
execution: fronted
endpoint: unix://$SOCK_DIR/agent.sock
model: fast
instruction: x
output: output
exec:
  mode: attested
  allow:
    - exe: env" "exec.mode is no longer supported; exec is always first-hand via a runtime"

run() { # $1 = workflow, $2 = input; sets OUT, RUNID, AUDIT
	OUT="$("$WORK/agenthof" run exec-operator "$1" --input "$2" \
		--as ci --groups exec-users --config "$WORK/config" \
		--log-dir "$WORK/logs" --artifact-dir "$WORK/artifacts" || true)"
	OUTS+=("$OUT")
	echo "$OUT"
	RUNID="$(echo "$OUT" | sed -n 's/^run \(r-[a-f0-9]*\) finished.*/\1/p')"
	[ -n "$RUNID" ] || fail "no run id in the output of $1"
	AUDIT="$("$WORK/agenthof" audit "$RUNID" --log-dir "$WORK/logs" --control-log "$WORK/control.jsonl")"
	OUTS+=("$AUDIT")
	echo "$AUDIT"
	echo "$AUDIT" | grep -q "ledger integrity: verified" || fail "$1: ledger not verified"
}
ATTESTED='\[runtime-attested: refexec'

# 1. The agent writes its note and the runtime runs `env` first-hand: the
#    output is the artifact, exactly the allowlisted variable, and the ledger
#    exec event carries the first-hand account — never the output.
run exec-runner "write:hello-$NONCE; exec-run:env"
echo "$OUT" | grep -q "finished: succeeded" || fail "exec-runner did not succeed"
echo "$AUDIT" | grep -Eq "exec env — exit 0 \(runtime\) $ATTESTED env pid [0-9]+ spawn 1\]" || fail "no first-hand exec line rendered"
grep -q '"mode":"runtime"' "$WORK/logs/$RUNID.jsonl" || fail "exec event is not mode runtime"
grep -q '"runtime_attestation":{"runtime":"refexec","session":"refexec-' "$WORK/logs/$RUNID.jsonl" || fail "no refexec attestation in the ledger"
grep -q '"credential_env":"","env_names":\["REFEXEC_E2E_MARKER"\],"materialization":""' "$WORK/logs/$RUNID.jsonl" || fail "attestation must be credential-less and name exactly the injected variable"
if grep -q "LEAKED_SECRET" "$WORK/logs/$RUNID.jsonl"; then fail "a non-allowlisted variable was attested"; fi
# The step's artifact preview is the output by design; the exec event must
# carry only its hash.
grep -q '"type":"exec"' "$WORK/logs/$RUNID.jsonl" || fail "no exec event in the ledger"
if grep '"type":"exec"' "$WORK/logs/$RUNID.jsonl" | grep -q "REFEXEC_E2E_MARKER=1"; then fail "the output body reached the exec event"; fi
ART="$WORK/artifacts/$(printf 'REFEXEC_E2E_MARKER=1\n' | sha_stdin)"
grep -q "\"output_sha\":\"$(basename "$ART")\"" "$WORK/logs/$RUNID.jsonl" || fail "the exec event's output_sha is not the artifact's hash"
[ -f "$ART" ] || { ls "$WORK/artifacts"; fail "no artifact equal to the command's output (the environment was not exactly the allowlist, or the store hashes differently)"; }
[ "$(cat "$WS/agent-note.txt")" = "hello-$NONCE" ] || fail "the agent did not write its note"
no_leak "not-for-the-command-$NONCE" "the non-allowlisted variable's value"
echo "first-hand run: artifact, clean environment, attestation, no output in the exec event — ok"

# 2. A non-zero exit is a failed exec that still carries the attestation.
run exec-runner "exec-run:false"
echo "$OUT" | grep -q "finished: failed" || fail "a non-zero exit must fail the step"
echo "$AUDIT" | grep -Eq "exec false — exit 1 \(runtime\) $ATTESTED false pid [0-9]+ spawn 1\]" || fail "failed exec not rendered with its attestation"

# 3. An off-allowlist command is refused before the runtime is asked. It is
#    harmless on purpose: the stand-in runtime runs commands on the host.
run exec-runner "exec-run:touch $WORK/canary"
echo "$OUT" | grep -q "finished: failed" || fail "an off-allowlist command must fail the step"
echo "$AUDIT" | grep -qF "exec touch $WORK/canary refused — command is not on the exec allowlist" || fail "refusal not rendered"
[ ! -e "$WORK/canary" ] || fail "an off-allowlist command ran"
[ "$(grep -c 'compartment started' "$WORK/refexec.err")" = 2 ] || fail "the runtime was asked to run something it should not have been (want 2 starts: env, false)"

# 4. Path gating: /exec/run is refused — and recorded — on an agent that
#    declares no exec. (The retired agent-asserted routes' recorded refusal
#    is proved in-process: internal/rungateway/exec_test.go and
#    cmd/agenthof/testdata/script/door_exec_runtime.txtar.)
run exec-none "exec-run:env"
echo "$OUT" | grep -q "finished: failed" || fail "run on an agent that declares no exec must fail the step"
echo "$AUDIT" | grep -q "exec env refused — first-hand exec is not declared for this agent" || fail "run refusal not recorded"

# 5. A runtime that attests a different command fails the call.
run exec-forged "exec-run:env"
echo "$OUT" | grep -q "finished: failed" || fail "a forged attestation must fail the step"
echo "$AUDIT" | grep -q "exec env failed — runtime attestation names a different command" || fail "forged attestation not recorded as failed"

# 6. A missing runtime, and a runtime behind a non-private directory: each a
#    failed exec with its own reason, the latter never dialed.
run exec-missing "exec-run:env"
echo "$AUDIT" | grep -q "exec env failed — exec runtime unreachable" || fail "missing runtime not recorded as failed"
run exec-open "exec-run:env"
echo "$AUDIT" | grep -q "exec env failed — exec runtime socket directory is not a private" || fail "open socket dir not recorded as failed"

# 7. The deadline: the gateway's exec.timeout cancels the call, the runtime
#    removes the compartment, and no command process outlives it.
run exec-slow "exec-run:sleep 3617"
echo "$OUT" | grep -q "finished: failed" || fail "a timed-out command must fail the step"
echo "$AUDIT" | grep -q "exec sleep 3617 failed — exec runtime call timed out" || fail "timeout not recorded as failed"
for i in $(seq 1 20); do
	grep -q "compartment removed" "$WORK/refexec.err" && ! pgrep -f "^sleep 3617$" >/dev/null 2>&1 && break
	[ "$i" = 20 ] && { pgrep -fl "^sleep 3617$" || true; fail "the cancelled command's compartment was not removed"; }
	sleep 0.5
done

no_leak "not-for-the-command-$NONCE" "the non-allowlisted variable's value"
echo "e2e-refexec-local: PASS"
