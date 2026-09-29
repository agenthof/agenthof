#!/usr/bin/env bash
# e2e-refbridge: prove the reference bridge runs in a compartment with no
# network and no credential environment, that a governed tool call through it
# succeeds (the step artifact is the echo plus the SHA-256 of the credential
# Agenthof injected, and the ledger records the tool_call with the bridge's
# first-hand attestation of what ran), that the child process is gone once
# the session ended, and that a bridge config missing a
# guardrail is refused before the compartment starts. The tool-agent runs on
# the host as a plain process: agent containment is refbox's proof, not this
# one's. Requires rootless podman, go and python3. Run from the repo root.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="${REFBRIDGE_IMAGE:-refbridge:test}"
NAME="${REFBRIDGE_NAME:-refbridge}"

SOCK_DIR="$(mktemp -d /tmp/rb.XXXXXX)"    # the bridge socket dir (mktemp makes it 0700)
export REFBRIDGE_SOCKET_DIR="$SOCK_DIR"
AGENT_DIR="$(mktemp -d /tmp/rb.XXXXXX)"   # the tool-agent's socket + the gateway socket dir; never the bridge's
WORK="$(mktemp -d /tmp/rb.XXXXXX)"
AGENT_PID=""
cleanup() {
	podman rm -f "$NAME" >/dev/null 2>&1 || true
	if [ -n "$AGENT_PID" ]; then
		kill "$AGENT_PID" >/dev/null 2>&1 || true
		wait "$AGENT_PID" >/dev/null 2>&1 || true
	fi
	rm -rf "$SOCK_DIR" "$AGENT_DIR" "$WORK"
}
trap cleanup EXIT
fail() {
	echo "e2e-refbridge: FAIL — $*"
	exit 1
}
sha() { python3 -c 'import hashlib, sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())' "$1"; }
unset AGENTHOF_TOKEN || true

go build -o "$WORK/agenthof" ./cmd/agenthof
go build -o "$WORK/tool-agent" ./examples/tool-agent
podman build -f deploy/refbridge/Containerfile -t "$IMAGE" .

# The bridge config, pointed at the private socket dir.
mkdir -p "$WORK/bridge-config"
sed "s|/run/agenthof-bridge|$SOCK_DIR|g" deploy/refbridge/bridge-config/refbridge.yaml >"$WORK/bridge-config/refbridge.yaml"
export REFBRIDGE_CONFIG_DIR="$WORK/bridge-config"

# Config is law before the compartment exists: a config without a
# materialization mode is refused by the same binary that would serve it.
mkdir -p "$WORK/bad-config"
sed '/materialization:/d' "$WORK/bridge-config/refbridge.yaml" >"$WORK/bad-config/refbridge.yaml"
if podman run --rm --network none --userns=keep-id --user "$(id -u):$(id -g)" -v "$WORK/bad-config:/config:ro" "$IMAGE" -check >/dev/null 2>"$WORK/check.err"; then
	fail "a bridge config without credential.materialization was accepted"
fi
grep -q "credential.materialization" "$WORK/check.err" || fail "the refusal did not name credential.materialization"

REFBRIDGE_DETACH=1 REFBRIDGE_IMAGE="$IMAGE" REFBRIDGE_NAME="$NAME" deploy/refbridge/refbridge-run.sh >/dev/null
for i in $(seq 1 30); do
	[ -S "$SOCK_DIR/stdio-tool.sock" ] && break
	[ "$i" = 30 ] && {
		echo "bridge socket never appeared"
		podman logs "$NAME" || true
		exit 1
	}
	sleep 1
done
[ "$(stat -c %a "$SOCK_DIR/stdio-tool.sock")" = 600 ] || fail "bridge socket is not mode 0600"

"$WORK/tool-agent" -socket "$AGENT_DIR/agent.sock" 2>"$WORK/agent.err" &
AGENT_PID=$!
for i in $(seq 1 30); do
	[ -S "$AGENT_DIR/agent.sock" ] && break
	[ "$i" = 30 ] && fail "agent socket never appeared"
	sleep 0.5
done

mkdir -p "$WORK/config"
cp -R deploy/refbridge/config/. "$WORK/config/"
sed -i "s|/run/agenthof-bridge-agent|$AGENT_DIR|g; s|/run/agenthof-bridge|$SOCK_DIR|g" "$WORK/config/gateway.yaml" "$WORK/config"/agents/*.yaml
printf 'refbox_socket_dir: %s\n' "$AGENT_DIR" >>"$WORK/config/gateway.yaml"

NONCE="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
# The tool credential lives with the HOST agenthof process only: exported
# after the compartment is already running and never passed with -e. The
# model key is a dummy the demo route requires to resolve.
export DEMO_TOOL_TOKEN="tool-secret-$NONCE"
export AGENTHOF_GATEWAY_KEY="host-side-dummy-key-$NONCE"

"$WORK/agenthof" apply --config "$WORK/config" --as ci --groups bridge-users
OUT="$("$WORK/agenthof" run bridge-operator bridge-demo --input "call echo hello-$NONCE; call credential; call environment" \
	--as ci --groups bridge-users --config "$WORK/config" \
	--log-dir "$WORK/logs" --artifact-dir "$WORK/artifacts")"
echo "$OUT"
echo "$OUT" | grep -q "finished: succeeded" || { podman logs "$NAME" || true; fail "run did not succeed"; }
RUNID="$(echo "$OUT" | sed -n 's/^run \(r-[a-f0-9]*\) finished.*/\1/p')"
AUDIT="$("$WORK/agenthof" audit "$RUNID" --log-dir "$WORK/logs")"
echo "$AUDIT"
echo "$AUDIT" | grep -q "ledger integrity: verified" || fail "ledger not verified"
for tool in echo credential environment; do
	echo "$AUDIT" | grep -Eq "tool $tool — args [0-9a-f]{8} \(static_env\)" || fail "no succeeded tool_call for $tool"
	echo "$AUDIT" | grep -Eq "tool $tool — args [0-9a-f]{8} \(static_env\) \[runtime-attested: refbridge /stdio-tool -credential-env DEMO_TOKEN pid [0-9]+ spawn 1\]" || fail "no runtime attestation rendered for $tool"
done
[ "$(grep -c '"runtime_attestation":{"runtime":"refbridge"' "$WORK/logs/$RUNID.jsonl")" = 3 ] || fail "want three attested tool_call events"
grep -q '"env_names":\["DEMO_TOKEN"\]' "$WORK/logs/$RUNID.jsonl" || fail "the bridge must attest an environment of exactly DEMO_TOKEN"
EXPECTED="$(printf 'hello-%s\n%s\nDEMO_TOKEN' "$NONCE" "$(sha "$DEMO_TOOL_TOKEN")")"
ART="$WORK/artifacts/$(sha "$EXPECTED")"
[ -f "$ART" ] || { ls "$WORK/artifacts"; fail "no artifact with the expected content's hash"; }
[ "$(cat "$ART")" = "$EXPECTED" ] || fail "artifact differs: the child's environment or credential was not as materialized"
if grep -rq "$DEMO_TOOL_TOKEN" "$WORK/logs" "$WORK/artifacts"; then fail "the credential value reached the ledger or an artifact"; fi
echo "governed call through the compartment: artifact, fingerprint, clean environment, runtime attestation — ok"

# Measure — not assert — what the bridge costs against the recipe's limits.
podman stats --no-stream --format 'compartment {{.Name}}: mem {{.MemUsage}} pids {{.PIDs}}' "$NAME" || true

# Containment. The session ended with the step (Agenthof sent DELETE), so
# the child must be gone; the compartment has no route out; no credential
# was ever in its environment; only the socket dir and the read-only config
# are mounted.
for i in $(seq 1 20); do
	[ "$(podman exec "$NAME" /probe -procs stdio-tool)" = 0 ] && break
	[ "$i" = 20 ] && fail "a stdio-tool child outlived its session"
	sleep 0.5
done
if podman exec "$NAME" /probe -dial 1.1.1.1:443; then
	fail "compartment reached the internet"
fi
if podman inspect "$NAME" --format '{{range .Config.Env}}{{println .}}{{end}}' |
	grep -Ei 'TOKEN|SECRET|PASSWORD|API_KEY|AGENTHOF_' >/dev/null; then
	echo "compartment has credential-like environment (names only):"
	podman inspect "$NAME" --format '{{range .Config.Env}}{{println .}}{{end}}' | cut -d= -f1
	exit 1
fi
MOUNTS="$(podman inspect "$NAME" --format '{{range .Mounts}}{{.Type}} {{.Source}} {{.Destination}}{{"\n"}}{{end}}')"
echo "$MOUNTS" | grep -q "bind $SOCK_DIR $SOCK_DIR" || fail "socket dir not mounted at the same path"
echo "$MOUNTS" | grep -q "bind $WORK/bridge-config /config" || fail "config not mounted"
[ "$(echo "$MOUNTS" | grep -c '^bind ' || true)" = 2 ] || fail "unexpected binds: $MOUNTS"
if echo "$MOUNTS" | grep -q "$AGENT_DIR"; then fail "the agent/gateway socket dir must never be mounted into the bridge"; fi
podman logs "$NAME" 2>&1 | grep -q "session ended; child torn down" || fail "no teardown logged"

echo "e2e-refbridge: PASS"
