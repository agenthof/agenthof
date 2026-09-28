#!/usr/bin/env bash
# e2e-langchain-local: prove the LangChain agent runs governed against the REAL
# agenthof binary over Unix sockets, with no container runtime. The agent
# serves its step endpoint on a Unix socket; the gateway listens on a Unix
# socket (refbox_socket_dir); a host-side stand-in provider answers with a
# per-run nonce. Asserts: the run succeeds, the artifact IS the nonce'd reply,
# the ledger records the model_call, the provider saw the HOST key (never the
# run token) and no X-Agenthof-* header, and a wrong logical model is refused
# with 403 by the real door and never reaches the provider.
# Requires go and a python with examples/langchain-agent/requirements.txt
# installed (PYTHON=... selects it; default python3). Runs on macOS and Linux.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PYTHON="${PYTHON:-python3}"

"$PYTHON" -c 'import langchain_openai, httpx' 2>/dev/null || {
	echo "e2e-langchain-local: $PYTHON lacks the pinned deps; run: $PYTHON -m pip install -r examples/langchain-agent/requirements.txt"
	exit 1
}

# Short on purpose: the gateway socket name is ~27 chars and a Unix socket
# path has a small OS length limit that a /var/folders/... temp dir exceeds.
SOCK_DIR="$(mktemp -d /tmp/lc.XXXXXX)"
WORK="$(mktemp -d)"
PIDS=()
cleanup() {
	# ${PIDS[@]+...}: an empty array under set -u is an error on bash 3.2 (macOS).
	# wait after kill: otherwise bash prints a "Terminated" line per child at exit.
	for p in ${PIDS[@]+"${PIDS[@]}"}; do
		kill "$p" >/dev/null 2>&1 || true
		wait "$p" >/dev/null 2>&1 || true
	done
	rm -rf "$SOCK_DIR" "$WORK"
}
trap cleanup EXIT
unset AGENTHOF_TOKEN || true

fail() {
	echo "e2e-langchain-local: FAIL — $*"
	exit 1
}

# Free loopback port for the stand-in provider, and a per-run nonce so that
# only a reply that really came back through the gateway can match.
PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
NONCE="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
REPLY="governed:$NONCE"
python3 scripts/fake-openai-provider.py --bind "127.0.0.1:$PORT" --reply "$REPLY" --log "$WORK/provider.jsonl" >/dev/null 2>"$WORK/provider.err" &
PIDS+=($!)
for i in $(seq 1 30); do
	python3 -c "import socket; socket.create_connection(('127.0.0.1', $PORT), 1).close()" >/dev/null 2>&1 && break
	[ "$i" = 30 ] && fail "provider never listened"
	sleep 0.2
done

# Two agent instances: one configured with the logical model, one deliberately
# sending a name the door must refuse.
"$PYTHON" examples/langchain-agent/agent.py -socket "$SOCK_DIR/lc.sock" --model fast 2>"$WORK/agent.err" &
PIDS+=($!)
"$PYTHON" examples/langchain-agent/agent.py -socket "$SOCK_DIR/lc-bad.sock" --model nope 2>"$WORK/agent-bad.err" &
PIDS+=($!)
for i in $(seq 1 60); do
	[ -S "$SOCK_DIR/lc.sock" ] && [ -S "$SOCK_DIR/lc-bad.sock" ] && break
	[ "$i" = 60 ] && {
		cat "$WORK/agent.err" "$WORK/agent-bad.err" || true
		fail "agent sockets never appeared"
	}
	sleep 0.5
done

# A hermetic config written from scratch (no sed: this runs on macOS too).
mkdir -p "$WORK/config/agents" "$WORK/config/workflows" "$WORK/config/roles"
cat >"$WORK/config/gateway.yaml" <<EOF
refbox_socket_dir: $SOCK_DIR
models:
  fast:
    endpoint: http://127.0.0.1:$PORT
    model: fast
    api_key_env: AGENTHOF_GATEWAY_KEY
defaults:
  model: fast
EOF
cat >"$WORK/config/agents/lc.yaml" <<EOF
name: lc
description: LangChain agent over a Unix socket (e2e)
model: fast
instruction: Answer the input with one model call.
output: reply
execution: fronted
endpoint: unix://$SOCK_DIR/lc.sock
EOF
cat >"$WORK/config/agents/lc-bad.yaml" <<EOF
name: lc-bad
description: LangChain agent that asks for a model it is not allowed (e2e)
model: fast
instruction: Answer the input with one model call.
output: reply
execution: fronted
endpoint: unix://$SOCK_DIR/lc-bad.sock
EOF
cat >"$WORK/config/workflows/lc-smoke.yaml" <<EOF
name: lc-smoke
description: One governed model call through the LangChain agent
steps:
  - name: answer
    agent: lc
EOF
cat >"$WORK/config/workflows/lc-bad-smoke.yaml" <<EOF
name: lc-bad-smoke
description: The door must refuse a wrong logical model
steps:
  - name: answer
    agent: lc-bad
EOF
cat >"$WORK/config/roles/lc-operator.yaml" <<EOF
name: lc-operator
description: Runs the LangChain e2e workflows
workflows: [lc-smoke, lc-bad-smoke]
allowed_groups: ["lc-users"]
EOF

go build -o "$WORK/agenthof" ./cmd/agenthof

# The provider key lives with the HOST agenthof process only. The stand-in
# ignores its value; without one the route does not resolve and the door 502s.
export AGENTHOF_GATEWAY_KEY="host-side-dummy-key-$NONCE"

"$WORK/agenthof" apply --config "$WORK/config" --as ci --groups lc-users

# 1. The governed call succeeds and the artifact is the nonce'd reply.
OUT="$("$WORK/agenthof" run lc-operator lc-smoke --input "say hi" \
	--as ci --groups lc-users --config "$WORK/config" \
	--log-dir "$WORK/logs" --artifact-dir "$WORK/artifacts")"
echo "$OUT"
echo "$OUT" | grep -q "finished: succeeded" || fail "run did not succeed"
RUNID="$(echo "$OUT" | sed -n 's/^run \(r-[a-f0-9]*\) finished.*/\1/p')"
AUDIT="$("$WORK/agenthof" audit "$RUNID" --log-dir "$WORK/logs")"
echo "$AUDIT"
echo "$AUDIT" | grep -qF "model fast — 3 prompt / 5 completion tokens" || fail "no succeeded model_call on the ledger"
echo "$AUDIT" | grep -q "ledger integrity: verified" || fail "ledger not verified"
SHA="$(python3 -c 'import hashlib, sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())' "$REPLY")"
[ -f "$WORK/artifacts/$SHA" ] || fail "no artifact with the reply's hash"
[ "$(cat "$WORK/artifacts/$SHA")" = "$REPLY" ] || fail "artifact is not the provider's nonce'd reply"

# 2. What reached the provider: the host key (never the run token), the
#    logical model, the chat-completions route, no X-Agenthof-* header.
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

# 3. A wrong logical model is refused by the real door (403) and never
#    reaches the provider; the agent reports a clean failed step.
OUT2="$("$WORK/agenthof" run lc-operator lc-bad-smoke --input "say hi" \
	--as ci --groups lc-users --config "$WORK/config" \
	--log-dir "$WORK/logs" --artifact-dir "$WORK/artifacts" || true)"
echo "$OUT2"
echo "$OUT2" | grep -q "finished: failed" || fail "wrong-model run did not fail"
RUNID2="$(echo "$OUT2" | sed -n 's/^run \(r-[a-f0-9]*\) finished.*/\1/p')"
AUDIT2="$("$WORK/agenthof" audit "$RUNID2" --log-dir "$WORK/logs")"
echo "$AUDIT2"
echo "$AUDIT2" | grep -qF 'model nope refused — model "nope" is not allowed for this agent' || fail "no refused model_call on the ledger"
echo "$AUDIT2" | grep -q "failed — model call failed" || fail "agent did not report the fixed failure reason"
[ "$(wc -l <"$WORK/provider.jsonl" | tr -d ' ')" = 1 ] || fail "provider was called on the refused path"

echo "e2e-langchain-local: PASS"
