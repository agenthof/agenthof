#!/usr/bin/env bash
# e2e-refexec: prove first-hand exec end to end with real rootless podman. The
# reference agent runs in a refbox compartment whose /work is a named volume;
# refexec runs on the host and, per command, starts a compartment with no
# network, a read-only root and that same volume; the agent writes a note on
# /work and asks Agenthof to run `cat` on it. Asserts: the step artifact is
# the note (the command saw the agent's file), the ledger records the exec
# with mode runtime and refexec's first-hand attestation, audit renders it,
# the exec event never carries the output body, the note is on the volume and
# survives the run; a command that tries the network fails inside its
# compartment and is recorded first-hand as failed; an off-allowlist command
# is refused before refexec is asked; no exec compartment is left behind;
# and a refexec config missing a guardrail is refused before anything
# starts. Requires rootless podman, go and python3. Run from the repo root.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="${REFBOX_IMAGE:-refbox-echo:test}"
NAME="${REFBOX_NAME:-refbox-exec}"
SOCKET="refbox-echo.sock"
EXEC_IMAGE="${REFEXEC_IMAGE:-docker.io/library/busybox:1.36.1}"
VOLUME="refexec-e2e-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"

SOCK_DIR="$(mktemp -d)"                    # the gateway + agent socket dir, mounted into refbox
export AGENTHOF_REFBOX_SOCKET_DIR="$SOCK_DIR"
EXEC_DIR="$(mktemp -d /tmp/rx.XXXXXX)"     # refexec's socket dir (mktemp makes it 0700); never mounted anywhere
WORK="$(mktemp -d)"
REFEXEC_PID=""
cleanup() {
	podman rm -f "$NAME" >/dev/null 2>&1 || true
	if [ -n "$REFEXEC_PID" ]; then
		kill "$REFEXEC_PID" >/dev/null 2>&1 || true
		wait "$REFEXEC_PID" >/dev/null 2>&1 || true
	fi
	podman ps -aq --filter 'name=^refexec-' | xargs -r podman rm -f >/dev/null 2>&1 || true
	podman volume rm -f "$VOLUME" >/dev/null 2>&1 || true
	rm -rf "$SOCK_DIR" "$EXEC_DIR" "$WORK"
}
trap cleanup EXIT
fail() {
	echo "e2e-refexec: FAIL — $*"
	exit 1
}
sha_stdin() { python3 -c 'import hashlib, sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())'; }
unset AGENTHOF_TOKEN || true

# Build and pull everything BEFORE anything starts: the compartments' wall
# clocks must not pay for a cold build or a pull. refexec runs podman with
# --pull=never, so the exec image is fetched here, by the operator.
go build -o "$WORK/agenthof" ./cmd/agenthof
go build -o "$WORK/refexec" ./deploy/refexec
podman build -f deploy/refbox/Containerfile -t "$IMAGE" .
podman pull "$EXEC_IMAGE" >/dev/null

# refexec's config, pointed at the private socket dir, this run's volume and
# the exec image.
sed "s|/run/agenthof-exec|$EXEC_DIR|; s|agenthof-work|$VOLUME|; s|docker.io/library/busybox:1.36.1|$EXEC_IMAGE|" deploy/refexec/exec-config/refexec.yaml >"$WORK/refexec.yaml"

# Config is law before anything starts: a config without a timeout is
# refused by the same binary that would serve it.
sed '/^timeout:/d' "$WORK/refexec.yaml" >"$WORK/refexec-bad.yaml"
if "$WORK/refexec" -config "$WORK/refexec-bad.yaml" -check >/dev/null 2>"$WORK/check.err"; then
	fail "a refexec config without a timeout was accepted"
fi
grep -q "timeout is required" "$WORK/check.err" || { cat "$WORK/check.err" >&2; fail "the refusal did not name timeout"; }

# refexec on the host, through its launcher (which creates the volume and
# prepares the 0700 socket dir).
REFEXEC_BIN="$WORK/refexec" REFEXEC_CONFIG="$WORK/refexec.yaml" deploy/refexec/refexec-run.sh 2>"$WORK/refexec.err" &
REFEXEC_PID=$!
for i in $(seq 1 30); do
	[ -S "$EXEC_DIR/refexec.sock" ] && break
	[ "$i" = 30 ] && { cat "$WORK/refexec.err" >&2; fail "refexec socket never appeared"; }
	sleep 0.5
done
[ "$(stat -c %a "$EXEC_DIR/refexec.sock")" = 600 ] || fail "refexec socket is not mode 0600"
[ "$(stat -c %a "$EXEC_DIR")" = 700 ] || fail "refexec socket dir is not 0700"
podman volume inspect "$VOLUME" >/dev/null || fail "the launcher did not create the workspace volume"

# The agent in refbox, with the shared workspace instead of a tmpfs.
REFBOX_DETACH=1 REFBOX_IMAGE="$IMAGE" REFBOX_NAME="$NAME" REFBOX_SOCKET="$SOCKET" REFBOX_WORKSPACE_VOLUME="$VOLUME" deploy/refbox/refbox-run.sh >/dev/null
for i in $(seq 1 30); do
	[ -S "$SOCK_DIR/$SOCKET" ] && break
	[ "$i" = 30 ] && { podman logs "$NAME" || true; fail "agent socket never appeared"; }
	sleep 1
done

mkdir -p "$WORK/config"
cp -R deploy/refexec/config/. "$WORK/config/"
sed -i "s|/run/agenthof-exec|$EXEC_DIR|g; s|/run/agenthof|$SOCK_DIR|g" "$WORK/config/gateway.yaml" "$WORK/config"/agents/*.yaml

NONCE="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
export AGENTHOF_GATEWAY_KEY="host-side-dummy-key-$NONCE"   # the model route is never called; the key only lets it resolve

"$WORK/agenthof" apply --config "$WORK/config" --control-log "$WORK/control.jsonl" --as ci --groups refbox-users

run() { # $1 = input; sets OUT, RUNID, AUDIT
	OUT="$("$WORK/agenthof" run refbox-exec-operator refbox-exec --input "$1" \
		--as ci --groups refbox-users --config "$WORK/config" --control-log "$WORK/control.jsonl" \
		--log-dir "$WORK/logs" --artifact-dir "$WORK/artifacts" || true)"
	echo "$OUT"
	RUNID="$(echo "$OUT" | sed -n 's/^run \(r-[a-f0-9]*\) finished.*/\1/p')"
	[ -n "$RUNID" ] || { podman logs "$NAME" || true; cat "$WORK/refexec.err" || true; fail "no run id"; }
	AUDIT="$("$WORK/agenthof" audit "$RUNID" --log-dir "$WORK/logs" --control-log "$WORK/control.jsonl")"
	echo "$AUDIT"
	echo "$AUDIT" | grep -q "ledger integrity: verified" || fail "ledger not verified"
}

# 1. The agent writes on the shared workspace; refexec's compartment reads it
#    first-hand; the ledger carries refexec's account and the exec event never
#    the output (the step's artifact preview is the output by design).
run "write:hello-$NONCE; exec-run:cat /work/agent-note.txt"
echo "$OUT" | grep -q "finished: succeeded" || { podman logs "$NAME" || true; cat "$WORK/refexec.err" || true; fail "run did not succeed"; }
echo "$AUDIT" | grep -Eq "exec cat /work/agent-note.txt — exit 0 \(runtime\) \[runtime-attested: refexec cat /work/agent-note.txt pid [0-9]+ spawn 1\]" || fail "no first-hand exec line rendered"
grep -q '"mode":"runtime"' "$WORK/logs/$RUNID.jsonl" || fail "exec event is not mode runtime"
grep -q '"runtime_attestation":{"runtime":"refexec","session":"refexec-' "$WORK/logs/$RUNID.jsonl" || fail "no refexec attestation in the ledger"
grep -q '"credential_env":"","env_names":\[\],"materialization":""' "$WORK/logs/$RUNID.jsonl" || fail "the attestation must be credential-less with no injected names (env_allow is empty)"
grep -q '"type":"exec"' "$WORK/logs/$RUNID.jsonl" || fail "no exec event in the ledger"
if grep '"type":"exec"' "$WORK/logs/$RUNID.jsonl" | grep -q "hello-$NONCE"; then fail "the output body reached the exec event"; fi
ART="$WORK/artifacts/$(printf 'hello-%s\n' "$NONCE" | sha_stdin)"
grep -q "\"output_sha\":\"$(basename "$ART")\"" "$WORK/logs/$RUNID.jsonl" || fail "the exec event's output_sha is not the artifact's hash"
[ -f "$ART" ] || { ls "$WORK/artifacts"; fail "no artifact equal to the note: the compartment did not see the agent's file"; }
MP="$(podman volume inspect "$VOLUME" --format '{{.Mountpoint}}')"
[ "$(cat "$MP/agent-note.txt")" = "hello-$NONCE" ] || fail "the note is not on the workspace volume"
grep -q "compartment started" "$WORK/refexec.err" || fail "refexec did not log the compartment start"
grep -q "compartment finished" "$WORK/refexec.err" || fail "refexec did not log the compartment finish"
echo "first-hand run on the shared workspace: artifact, attestation, no output in the exec event — ok"

# 2. No egress from an exec compartment: wget through the door fails inside
#    --network none, and the ledger records that first-hand as a failed exec.
run "exec-run:wget -T 3 -q -O - http://1.1.1.1/"
echo "$OUT" | grep -q "finished: failed" || fail "a command that needs the network must fail"
echo "$AUDIT" | grep -Eq "exec wget -T 3 -q -O - http://1.1.1.1/ — exit [1-9][0-9]* \(runtime\) \[runtime-attested: refexec wget" || fail "the network failure was not recorded first-hand"

# 3. An off-allowlist command is refused before refexec is asked.
run "exec-run:sh -c id"
echo "$OUT" | grep -q "finished: failed" || fail "an off-allowlist command must fail the step"
echo "$AUDIT" | grep -q "exec sh -c id refused — command is not on the exec allowlist" || fail "refusal not rendered"
[ "$(grep -c 'compartment started' "$WORK/refexec.err")" = 2 ] || fail "refexec was asked to run something it should not have been (want 2 starts)"

# Measure — not assert — what the agent compartment costs.
podman stats --no-stream --format 'compartment {{.Name}}: mem {{.MemUsage}} pids {{.PIDs}}' "$NAME" || true

# Containment of the agent compartment is unchanged but for the workspace:
# the socket dir and the volume are its only mounts, /work is no tmpfs, no
# credential is in its environment, and it has no route out.
MOUNTS="$(podman inspect "$NAME" --format '{{range .Mounts}}{{.Type}} {{.Source}} {{.Destination}}{{"\n"}}{{end}}')"
echo "$MOUNTS" | grep -q "bind $SOCK_DIR $SOCK_DIR" || fail "socket dir not mounted"
echo "$MOUNTS" | grep -q "^volume .* /work$" || fail "the workspace volume is not mounted at /work: $MOUNTS"
[ "$(echo "$MOUNTS" | grep -c '^bind ' || true)" = 1 ] || fail "unexpected binds: $MOUNTS"
if podman inspect "$NAME" --format '{{json .HostConfig.Tmpfs}}' | grep -q '/work'; then fail "/work must not be a tmpfs when the volume knob is set"; fi
if echo "$MOUNTS" | grep -q "$EXEC_DIR"; then fail "refexec's socket dir must never be mounted into the agent compartment"; fi
if podman inspect "$NAME" --format '{{range .Config.Env}}{{println .}}{{end}}' | grep -Ei 'TOKEN|SECRET|PASSWORD|API_KEY|AGENTHOF_' >/dev/null; then
	fail "compartment has credential-like environment"
fi
if podman exec "$NAME" /probe -dial 1.1.1.1:443; then
	fail "agent compartment reached the internet"
fi

# No exec compartment outlives its command; the workspace outlives the run
# but not the recipe.
[ -z "$(podman ps -aq --filter 'name=^refexec-')" ] || { podman ps -a --filter 'name=^refexec-'; fail "an exec compartment was left behind"; }
podman rm -f "$NAME" >/dev/null
[ "$(cat "$MP/agent-note.txt")" = "hello-$NONCE" ] || fail "the note must survive the agent compartment (the volume is recipe-scoped)"
podman volume rm -f "$VOLUME" >/dev/null
[ ! -e "$MP/agent-note.txt" ] || fail "the note must go with the volume"

echo "e2e-refexec: PASS"
