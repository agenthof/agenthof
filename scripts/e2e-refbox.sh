#!/usr/bin/env bash
# e2e-refbox: prove a reference agent finishes a run inside a compartment that
# has no network, no injected credentials, and an ephemeral workspace — and,
# with REFBOX_MODEL_PROOF=1, that its model call went through Agenthof and
# nowhere else: the step artifact equals the reply a host-side stand-in
# provider returned for this run, the run ledger records the model_call, the
# provider saw the host key (never the run token), and the compartment cannot
# reach that provider's address. Requires rootless podman, go and python3.
# Run from the repo root. Knobs (all optional; the defaults are the echo agent):
#   REFBOX_CONTAINERFILE  image recipe                 (deploy/refbox/Containerfile)
#   REFBOX_IMAGE          image tag                    (refbox-echo:test)
#   REFBOX_NAME           container name               (refbox-echo)
#   REFBOX_SOCKET         agent socket file name       (refbox-echo.sock)
#   REFBOX_WORKFLOW       workflow to run              (refbox-smoke)
#   REFBOX_SOCKET_WAIT    seconds to wait for the agent socket (30)
#   REFBOX_MODEL_PROOF    1 = also assert the governed model call (0)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CONTAINERFILE="${REFBOX_CONTAINERFILE:-deploy/refbox/Containerfile}"
IMAGE="${REFBOX_IMAGE:-refbox-echo:test}"
NAME="${REFBOX_NAME:-refbox-echo}"
SOCKET="${REFBOX_SOCKET:-refbox-echo.sock}"
WORKFLOW="${REFBOX_WORKFLOW:-refbox-smoke}"
SOCKET_WAIT="${REFBOX_SOCKET_WAIT:-30}"
MODEL_PROOF="${REFBOX_MODEL_PROOF:-0}"

# Hermetic override. The recipe default is $XDG_RUNTIME_DIR/agenthof, which a
# systemd host provides as a user-owned tmpfs. This job does not prove that
# default is writable; it points the recipe and a rewritten copy of the demo
# config at a private directory.
SOCK_DIR="$(mktemp -d)"
export AGENTHOF_REFBOX_SOCKET_DIR="$SOCK_DIR"
WORK="$(mktemp -d)"
PROVIDER_PID=""
cleanup() {
	podman rm -f "$NAME" >/dev/null 2>&1 || true
	if [ -n "$PROVIDER_PID" ]; then
		kill "$PROVIDER_PID" >/dev/null 2>&1 || true
		wait "$PROVIDER_PID" >/dev/null 2>&1 || true
	fi
	rm -rf "$SOCK_DIR" "$WORK"
}
trap cleanup EXIT

fail() {
	echo "e2e-refbox: FAIL — $*"
	exit 1
}

unset AGENTHOF_TOKEN || true

# Build everything the host needs BEFORE the compartment starts: the recipe's
# --timeout=300 wall clock must not pay for a cold go build.
go build -o "$WORK/agenthof" ./cmd/agenthof
podman build -f "$CONTAINERFILE" -t "$IMAGE" .

# A stand-in model provider bound to a host address. The gateway (on the host)
# is routed to it; the compartment must not reach it — the probe dials this
# exact address later. The reply carries a per-run nonce, so an agent that
# never called the provider cannot produce a matching artifact.
HOST_IP="$(ip -4 route get 1.1.1.1 | awk '{for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit }}')"
[ -n "$HOST_IP" ] || fail "no host address"
PROVIDER_PORT="$(python3 -c "import socket; s=socket.socket(); s.bind(('$HOST_IP', 0)); print(s.getsockname()[1]); s.close()")"
NONCE="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
REPLY="governed:$NONCE"
python3 scripts/fake-openai-provider.py --bind "$HOST_IP:$PROVIDER_PORT" --reply "$REPLY" --log "$WORK/provider.jsonl" >/dev/null 2>&1 &
PROVIDER_PID=$!
for i in $(seq 1 20); do
	python3 -c "import socket; socket.create_connection(('$HOST_IP', $PROVIDER_PORT), 1).close()" >/dev/null 2>&1 && break
	[ "$i" = 20 ] && fail "stand-in provider never listened"
	sleep 0.2
done

REFBOX_DETACH=1 REFBOX_IMAGE="$IMAGE" REFBOX_NAME="$NAME" REFBOX_SOCKET="$SOCKET" deploy/refbox/refbox-run.sh >/dev/null

for i in $(seq 1 "$SOCKET_WAIT"); do
	[ -S "$SOCK_DIR/$SOCKET" ] && break
	[ "$i" = "$SOCKET_WAIT" ] && {
		echo "agent socket never appeared"
		podman logs "$NAME" || true
		exit 1
	}
	sleep 1
done

mkdir -p "$WORK/config"
cp -R deploy/refbox/config/. "$WORK/config/"
sed -i "s|/run/agenthof|$SOCK_DIR|g" "$WORK/config/gateway.yaml" "$WORK/config"/agents/*.yaml
sed -i "s|http://localhost:4000|http://$HOST_IP:$PROVIDER_PORT|" "$WORK/config/gateway.yaml"

# The provider key lives with the HOST agenthof process only: exported after
# the compartment is already running and never passed with -e. The stand-in
# ignores its value; without one the route does not resolve and the door 502s.
export AGENTHOF_GATEWAY_KEY="host-side-dummy-key-$NONCE"

"$WORK/agenthof" apply --config "$WORK/config" --control-log "$WORK/control.jsonl" --as ci --groups refbox-users
OUT="$("$WORK/agenthof" run refbox-operator "$WORKFLOW" --input hi \
	--as ci --groups refbox-users --config "$WORK/config" \
	--log-dir "$WORK/logs" --artifact-dir "$WORK/artifacts")"
echo "$OUT"
echo "$OUT" | grep -q "finished: succeeded" || fail "run did not succeed"

if [ "$MODEL_PROOF" = 1 ]; then
	# (a) the artifact IS the provider's nonce'd reply, (b) the ledger records
	# the model_call, and the provider saw the host key, the logical model,
	# the chat-completions route, and no X-Agenthof-* header. (c) — no other
	# path out — is the probe dial to the provider's address below.
	RUNID="$(echo "$OUT" | sed -n 's/^run \(r-[a-f0-9]*\) finished.*/\1/p')"
	AUDIT="$("$WORK/agenthof" audit "$RUNID" --log-dir "$WORK/logs" --control-log "$WORK/control.jsonl")"
	echo "$AUDIT"
	echo "$AUDIT" | grep -qF "model fast — 3 prompt / 5 completion tokens" || fail "no succeeded model_call on the ledger"
	echo "$AUDIT" | grep -q "ledger integrity: verified" || fail "ledger not verified"
	SHA="$(python3 -c 'import hashlib, sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())' "$REPLY")"
	[ -f "$WORK/artifacts/$SHA" ] || fail "no artifact with the reply's hash"
	[ "$(cat "$WORK/artifacts/$SHA")" = "$REPLY" ] || fail "artifact is not the provider's nonce'd reply"
	python3 - "$WORK/provider.jsonl" "$AGENTHOF_GATEWAY_KEY" <<'EOF'
import json, sys
lines = [json.loads(l) for l in open(sys.argv[1], encoding="utf-8")]
assert len(lines) == 1, f"expected exactly one provider call, saw {len(lines)}"
r = lines[0]
assert r["path"] == "/v1/chat/completions", r["path"]
assert r["authorization"] == "Bearer " + sys.argv[2], "provider did not see the host key"
assert r["model"] == "fast", r["model"]
assert not [h for h in r["headers"] if h.startswith("x-agenthof")], r["headers"]
print("provider saw: host key injected, model fast, /v1/chat/completions, no X-Agenthof-* headers")
EOF
fi

# Measure — not assert — what this runtime costs against the recipe's limits
# (--memory=256m, --pids-limit=64), so the knobs are sized from evidence.
podman stats --no-stream --format 'compartment {{.Name}}: mem {{.MemUsage}} pids {{.PIDs}}' "$NAME" || true

if podman exec "$NAME" /probe -dial 1.1.1.1:443; then
	fail "compartment reached the internet"
fi
if podman exec "$NAME" /probe -dial "$HOST_IP:$PROVIDER_PORT"; then
	fail "compartment reached the model provider directly"
fi

if podman inspect "$NAME" --format '{{range .Config.Env}}{{println .}}{{end}}' |
	grep -Ei 'TOKEN|SECRET|PASSWORD|API_KEY|AGENTHOF_' >/dev/null; then
	echo "compartment has credential-like environment"
	podman inspect "$NAME" --format '{{range .Config.Env}}{{println .}}{{end}}'
	exit 1
fi
if podman inspect "$NAME" --format '{{json .Mounts}}' | grep -Eq 'docker\.sock|podman\.sock'; then
	fail "compartment can see a runtime socket"
fi

MOUNTS="$(podman inspect "$NAME" --format '{{range .Mounts}}{{.Type}} {{.Source}} {{.Destination}}{{"\n"}}{{end}}')"
echo "$MOUNTS" | grep -q "bind $SOCK_DIR $SOCK_DIR"
BIND_COUNT="$(echo "$MOUNTS" | grep -c '^bind ' || true)"
[ "$BIND_COUNT" = 1 ] || fail "unexpected binds: $MOUNTS"
podman inspect "$NAME" --format '{{json .HostConfig.Tmpfs}}' | grep -q '/work'

# A file on the tmpfs must not appear on the host, and must be gone once the
# compartment is removed (a new container gets a new tmpfs).
podman exec "$NAME" /probe -touch /work/marker
podman rm -f "$NAME" >/dev/null
if find "$SOCK_DIR" -name marker | grep -q .; then
	fail "workspace file leaked onto the host"
fi

echo "e2e-refbox ($WORKFLOW): PASS"
