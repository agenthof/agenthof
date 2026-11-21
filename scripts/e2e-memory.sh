#!/usr/bin/env bash
# e2e-memory: prove the governed memory store against a REAL vector backend —
# the one tier that runs the memory-store MCP server (fronted by refbridge,
# governed by the agenthof BINARY through the tool door) against an actual
# Qdrant server, and proves the embedded and Qdrant backends agree.
#
# The bridge and the store run on the HOST (inside the Lima VM on macOS); Qdrant
# is a digest-pinned container published on 127.0.0.1 only, as
# scripts/e2e-embeddings.sh runs its backend. The same governed flow runs once
# per backend:
#   1. a memory-agent with a read-write grant upserts five known 4-d vectors
#      (caller ids, so each id is a derived UUID) and searches the nearest 3:
#      the ledger carries refbridge-attested tool_call events and completes;
#   2. a search-only agent's memory_upsert is refused ("tool is not available
#      to this run"), recording no resource and no attestation;
#   3. the bridge (and so the store process) is RESTARTED, and a search from a
#      separate run still finds the data — for the embedded backend the file on
#      disk, for Qdrant the server's collection;
#   4. the credential value is in no ledger, artifact, or log.
# The seam proof then compares the two legs: the SAME top-k ids (compared by the
# derived UUID, never byte-for-byte) with the scores equal within an epsilon
# and well separated, so the ranking cannot hinge on a float32 tie. Metadata is
# not returned by memory_search, so it is not part of the seam.
#
# Pinned: the Qdrant IMAGE, by the multi-arch INDEX digest of the v1.20.2 tag
# (resolved from the registry: the tag's Docker-Content-Digest, which `latest`
# also pointed at on 2026-11-21). The search is `exact`, so the result does not
# depend on Qdrant's approximate index.
#
# Requires: podman (rootless), go, curl, python3. Run from the repo root. On
# macOS run it inside the Lima VM (deploy/lima), as with the other real-backend
# tiers. QDRANT_PORT selects the host port (default 6333); KEEP=1 (or --keep)
# keeps the container and the work directories. Local-by-judgment only — never
# CI (a real container backend, like the podman combined run).
set -euo pipefail

ME="e2e-memory"
QDRANT_VERSION="v1.20.2"
IMAGE="docker.io/qdrant/qdrant:$QDRANT_VERSION@sha256:d277592721d2e3b73f9b797b53cf05e6a5bb2134f6d13fdbda4ca51782afbcac"
CONTAINER="agenthof-memory-e2e"
PORT="${QDRANT_PORT:-6333}"
QDRANT_URL="http://127.0.0.1:$PORT"

KEEP="${KEEP:-0}" # KEEP=1 env, or --keep (as deploy/lima/lima.sh forwards it)
for a in "$@"; do
	case "$a" in
	--keep) KEEP=1 ;;
	*)
		echo "$ME: unknown argument: $a (want: [--keep])" >&2
		exit 2
		;;
	esac
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
	echo "$ME: FAIL — $*" >&2
	exit 1
}
command -v podman >/dev/null 2>&1 || fail "need rootless podman on PATH"
for tool in go python3 curl; do
	command -v "$tool" >/dev/null 2>&1 || fail "$tool is required"
done

# Short on purpose: Unix socket paths have a small OS length limit.
BASE="$(mktemp -d /tmp/me.XXXXXX)"
WORK="$(mktemp -d)"
PIDS=()
BRIDGE_PID=""
cleanup() {
	local rc=$? # must be first: later commands overwrite $?
	if [ "$KEEP" = 1 ]; then
		echo "kept: container '$CONTAINER' up on $QDRANT_URL, dirs $BASE $WORK, pids ${PIDS[*]-none} $BRIDGE_PID"
		echo "inspect: podman logs $CONTAINER ; tear down: podman rm -f $CONTAINER ; kill ${PIDS[*]-} $BRIDGE_PID ; rm -rf $BASE $WORK"
		return 0
	fi
	# On a failure, surface the server's own log before it is destroyed.
	[ "$rc" = 0 ] || podman logs --tail 40 "$CONTAINER" 2>&1 || true
	for p in ${PIDS[@]+"${PIDS[@]}"} $BRIDGE_PID; do
		kill "$p" >/dev/null 2>&1 || true
		wait "$p" >/dev/null 2>&1 || true
	done
	podman rm -f "$CONTAINER" >/dev/null 2>&1 || true
	rm -rf "$BASE" "$WORK" || true
}
trap cleanup EXIT
unset AGENTHOF_TOKEN || true

runid_of() { printf '%s\n' "$1" | sed -n 's/^run \(r-[a-f0-9]*\) finished.*/\1/p'; }
ere_escape() { printf '%s' "$1" | sed 's/[][\\.*^$+?(){}|]/\\&/g'; }

# --- 1. Qdrant: drop any leftover of THIS container, refuse a foreign
#     listener on the port, start the pinned image on loopback only. ---
podman rm -f "$CONTAINER" >/dev/null 2>&1 || true
if curl -sS -o /dev/null "$QDRANT_URL/" 2>/dev/null; then
	fail "something already listens on $QDRANT_URL (a foreign process?); set QDRANT_PORT to a free port"
fi
echo "starting Qdrant $QDRANT_VERSION (pulling the pinned image on first run may take a while)..."
podman run -d --name "$CONTAINER" -p "127.0.0.1:$PORT:6333" "$IMAGE" >/dev/null
echo "waiting for Qdrant..."
for i in $(seq 1 120); do
	curl -fsS -o /dev/null "$QDRANT_URL/readyz" 2>/dev/null && break
	[ "$i" = 120 ] && fail "Qdrant never became ready on $QDRANT_URL"
	sleep 1
done
echo "Qdrant is up on $QDRANT_URL"

# --- 2. build the binaries (run on the host). ---
echo "building agenthof, refbridge, memory-store, memory-agent..."
go build -o "$WORK/agenthof" ./cmd/agenthof
go build -o "$WORK/refbridge" ./deploy/refbridge
go build -o "$WORK/memory-store" ./examples/memory-store
go build -o "$WORK/memory-agent" ./examples/memory-agent

NONCE="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
export MEMORY_TOKEN="memory-secret-$NONCE"
export AGENTHOF_GATEWAY_KEY="host-side-dummy-key-$NONCE" # the model route is never called; the key only lets it resolve

# Five known vectors against the query [1,0,0,0]. Cosines: a 1.0, b 0.7071,
# c 0.4472, d 0.0, e -1.0 — the top three are well separated (gaps >= 0.25), so
# neither backend's ranking can hinge on a float32 tie.
UPSERTS='[
{"collection":"seam","id":"seam-a","text":"seam a","vector":[1,0,0,0],"metadata":{"k":"a","n":{"x":1,"y":[1,2]}}},
{"collection":"seam","id":"seam-b","text":"seam b","vector":[1,1,0,0],"metadata":{"k":"b"}},
{"collection":"seam","id":"seam-c","text":"seam c","vector":[1,2,0,0],"metadata":{"k":"c"}},
{"collection":"seam","id":"seam-d","text":"seam d","vector":[0,1,0,0],"metadata":{"k":"d"}},
{"collection":"seam","id":"seam-e","text":"seam e","vector":[-1,0,0,0],"metadata":{"k":"e"}}]'
UPSERTS="$(printf '%s' "$UPSERTS" | tr -d '\n')"
QUERY='[1,0,0,0]'
SEARCH="{\"collection\":\"seam\",\"vector\":$QUERY,\"k\":3}"

# leg NAME: the whole governed flow against one backend. Leaves
# $BASE/NAME.ids (top-k "id score" lines, in rank order) for the seam proof.
leg() {
	local name="$1"
	local ldir="$BASE/$name" sock="$BASE/$name/s" bridge="$BASE/$name/b" store="$BASE/$name/d"
	local cfg="$WORK/$name/config" logs="$WORK/$name/logs" arts="$WORK/$name/artifacts"
	mkdir -p "$sock" "$bridge" "$store" "$cfg/agents" "$cfg/workflows" "$cfg/roles" "$logs" "$arts"
	chmod 0700 "$bridge" "$store"
	local store_file="$store/memory.json" cmd cmd_json
	case "$name" in
	embedded) cmd=("$WORK/memory-store" -backend embedded -store-file "$store_file" -collections seam -credential-env MEMORY_TOKEN) ;;
	qdrant) cmd=("$WORK/memory-store" -backend qdrant -qdrant-url "$QDRANT_URL" -collections seam -credential-env MEMORY_TOKEN) ;;
	esac
	cmd_json="$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1:]))' "${cmd[@]}")"
	local egress="[]"
	[ "$name" = qdrant ] && egress="[\"127.0.0.1:$PORT\"]"
	cat >"$ldir/bridge.yaml" <<EOF
socket: $bridge/memory.sock
command: $cmd_json
credential:
  env: MEMORY_TOKEN
  materialization: env-at-spawn
env_passthrough: []
egress:
  allow: $egress
sessions:
  max: 4
  idle_timeout: 10m
  max_lifetime: 30m
EOF
	start_bridge() {
		rm -f "$bridge/memory.sock"
		"$WORK/refbridge" -config "$ldir/bridge.yaml" 2>>"$ldir/bridge.err" &
		BRIDGE_PID=$!
		for i in $(seq 1 60); do
			[ -S "$bridge/memory.sock" ] && return 0
			sleep 0.5
		done
		cat "$ldir/bridge.err" || true
		fail "$name: the bridge socket never appeared"
	}
	start_bridge
	"$WORK/memory-agent" -socket "$sock/agent.sock" 2>"$ldir/agent.err" &
	PIDS+=($!)
	for i in $(seq 1 60); do
		[ -S "$sock/agent.sock" ] && break
		[ "$i" = 60 ] && fail "$name: the agent socket never appeared"
		sleep 0.5
	done

	cat >"$cfg/gateway.yaml" <<EOF
refbox_socket_dir: $sock
models:
  fast:
    endpoint: http://127.0.0.1:9/v1
    model: fast
    api_key_env: AGENTHOF_GATEWAY_KEY
defaults:
  model: fast
tools:
  memory:
    kind: mcp
    url: unix://$bridge/memory.sock
    runtime: refbridge
    credential_source: static_env
    token_env: MEMORY_TOKEN
    read_only_tools: [memory_search]
EOF
	local a mode
	for a in writer:read-write reader:read-only; do
		mode="${a#*:}"
		a="${a%%:*}"
		cat >"$cfg/agents/memory-$a.yaml" <<EOF
name: memory-$a
description: Memory $a (real-backend e2e)
model: fast
instruction: Run the memory script.
output: reply
execution: fronted
endpoint: unix://$sock/agent.sock
tools:
  - resource: memory
    tools: ["*"]
    mode: $mode
EOF
		cat >"$cfg/workflows/memory-$a.yaml" <<EOF
name: memory-$a
description: One step as the $a agent
steps:
  - name: call
    agent: memory-$a
EOF
	done
	cat >"$cfg/roles/memory-operator.yaml" <<EOF
name: memory-operator
description: Runs the memory e2e workflows
workflows: [memory-writer, memory-reader]
allowed_groups: ["memory-users"]
control: [apply]
EOF

	local ctl="$WORK/$name/control.jsonl"
	"$WORK/agenthof" apply --config "$cfg" --control-log "$ctl" --as ci --groups memory-users >/dev/null
	run() { # $1 = workflow, $2 = step input JSON
		"$WORK/agenthof" run memory-operator "$1" --input "$2" \
			--as ci --groups memory-users --config "$cfg" --control-log "$ctl" \
			--log-dir "$logs" --artifact-dir "$arts"
	}
	audit() { "$WORK/agenthof" audit "$1" --log-dir "$logs" --control-log "$ctl"; }
	check_audit() { # $1 = run id, $2 = what
		local a
		a="$(audit "$1")"
		echo "$a"
		grep -q "ledger integrity: verified" <<<"$a" || fail "$name: $2 ledger not verified"
		grep -q "ledger completeness: complete (" <<<"$a" || fail "$name: $2 ledger does not account for itself"
		AUDIT_OUT="$a"
	}

	# a. upsert five + search top 3, one session of the read-write agent.
	local out1 id1 ledger1 art1
	out1="$(run memory-writer "{\"upserts\":$UPSERTS,\"searches\":[$SEARCH]}" 2>"$ldir/run1.err")" || {
		cat "$ldir/run1.err" "$ldir/bridge.err" || true
		fail "$name: the upsert/search run failed"
	}
	echo "$out1"
	grep -q "finished: succeeded" <<<"$out1" || fail "$name: the upsert/search run did not succeed"
	id1="$(runid_of "$out1")"
	[ -n "$id1" ] || fail "$name: no run id for the upsert/search run"
	check_audit "$id1" "upsert/search run"
	ledger1="$logs/$id1.jsonl"
	[ "$(grep -c '"runtime_attestation":{"runtime":"refbridge"' "$ledger1")" = 6 ] || fail "$name: want six attested tool_call events (five upserts, one search)"
	[ "$(grep -Ec "tool memory_upsert — args [0-9a-f]{8} \(static_env\) \[runtime-attested: refbridge $(ere_escape "$WORK/memory-store") " <<<"$AUDIT_OUT")" = 5 ] || fail "$name: audit does not render five attested memory_upsert calls"
	art1="$(grep -rlE '^upserted ' "$arts" | head -n1 || true)"
	[ -n "$art1" ] || fail "$name: no artifact from the upsert/search run"
	[ "$(grep -Ec '^upserted [0-9a-f-]{36}$' "$art1")" = 5 ] || fail "$name: want five 'upserted <uuid>' lines"
	[ "$(grep -Ec '^hit [0-9a-f-]{36} -?[0-9]+\.[0-9]{4}$' "$art1")" = 3 ] || fail "$name: want three 'hit <uuid> <score>' lines"
	local ida idb idc
	ida="$(sed -n '1s/^upserted //p' "$art1")"
	idb="$(sed -n '2s/^upserted //p' "$art1")"
	idc="$(sed -n '3s/^upserted //p' "$art1")"
	[ "$(grep '^hit ' "$art1")" = "$(printf 'hit %s 1.0000\nhit %s 0.7071\nhit %s 0.4472' "$ida" "$idb" "$idc")" ] \
		|| fail "$name: want exactly a, b, c in that order at 1.0000, 0.7071, 0.4472"
	grep '^hit ' "$art1" | sed 's/^hit //' >"$BASE/$name.ids"
	sed -n 's/^upserted //p' "$art1" >"$BASE/$name.upserted"
	echo "$name: upsert + search: nearest three in order with exact scores — ok"

	# b. the search-only agent's upsert is refused; nothing is recorded as run.
	local out2 id2 ledger2
	if out2="$(run memory-reader "{\"upserts\":[{\"collection\":\"seam\",\"text\":\"forbidden $NONCE\",\"vector\":[0,0,1,0],\"metadata\":{}}]}" 2>&1)"; then
		fail "$name: the search-only agent's memory_upsert was not refused"
	fi
	echo "$out2"
	grep -q "finished: failed" <<<"$out2" || fail "$name: the refused run did not finish failed"
	id2="$(runid_of "$out2")"
	[ -n "$id2" ] || fail "$name: no run id for the refused run"
	check_audit "$id2" "refused run"
	grep -q "tool memory_upsert refused — tool is not available to this run" <<<"$AUDIT_OUT" || fail "$name: memory_upsert was not refused with the read-only reason"
	ledger2="$logs/$id2.jsonl"
	if grep -q '"runtime_attestation"' "$ledger2"; then fail "$name: the refused call recorded an attested tool_call"; fi
	if grep -q '"resources_touched"' "$ledger2"; then fail "$name: the refused call recorded a touched resource"; fi
	echo "$name: read-only grant: memory_upsert refused — ok"

	# c. RESTART the bridge (a new store process) and search from a separate run.
	if [ "$name" = embedded ]; then
		[ -s "$store_file" ] || fail "embedded: the store file is missing or empty after the writes"
	fi
	kill "$BRIDGE_PID" >/dev/null 2>&1 || true
	wait "$BRIDGE_PID" >/dev/null 2>&1 || true
	start_bridge
	local out3 id3 art3
	out3="$(run memory-reader "{\"searches\":[$SEARCH]}" 2>"$ldir/run3.err")" || {
		cat "$ldir/run3.err" "$ldir/bridge.err" || true
		fail "$name: the search after the restart failed"
	}
	echo "$out3"
	grep -q "finished: succeeded" <<<"$out3" || fail "$name: the search after the restart did not succeed"
	id3="$(runid_of "$out3")"
	[ -n "$id3" ] && [ "$id3" != "$id1" ] || fail "$name: the post-restart search is not a separate run"
	check_audit "$id3" "post-restart run"
	art3=""
	for f in "$arts"/*; do
		[ "$f" != "$art1" ] && grep -q '^hit ' "$f" && art3="$f"
	done
	[ -n "$art3" ] || fail "$name: no artifact from the post-restart search"
	[ "$(grep '^hit ' "$art3" | sed 's/^hit //')" = "$(cat "$BASE/$name.ids")" ] || fail "$name: the post-restart search differs from the original"
	echo "$name: persistence: the restarted store returns the same top three — ok"

	# d. the credential is in no ledger, artifact, or log.
	if grep -rqF -- "$MEMORY_TOKEN" "$logs" "$arts" "$ctl" "$ldir/bridge.err" "$ldir/agent.err" "$ldir/run1.err" "$ldir/run3.err" "$store"; then
		fail "$name: the credential value reached a ledger, artifact, log, or the store"
	fi
	echo "$name: the credential value is in no ledger, artifact, or log — ok"

	kill "$BRIDGE_PID" >/dev/null 2>&1 || true
	wait "$BRIDGE_PID" >/dev/null 2>&1 || true
	BRIDGE_PID=""
}

leg embedded
leg qdrant

# --- the seam proof: both backends agree. Ids are compared as the derived
# UUIDs, never byte-for-byte on a payload; scores within an epsilon (float32
# both sides) and well separated. ---
python3 - "$BASE/embedded.ids" "$BASE/qdrant.ids" "$BASE/embedded.upserted" "$BASE/qdrant.upserted" <<'PY' || fail "the embedded and Qdrant backends disagree"
import sys
def rows(p):
    return [(l.split()[0], float(l.split()[1])) for l in open(p) if l.strip()]
emb, qd = rows(sys.argv[1]), rows(sys.argv[2])
assert [i for i, _ in emb] == [i for i, _ in qd], "top-k ids differ: %r vs %r" % (emb, qd)
assert len(set(i for i, _ in emb)) == 3, "top-k ids are not three distinct ids"
EPS = 5e-4  # the artifact rounds to four decimals; float32 on both sides
for (i, a), (_, b) in zip(emb, qd):
    assert abs(a - b) <= EPS, "score for %s differs: %s vs %s" % (i, a, b)
scores = [s for _, s in emb]
assert all(scores[k] - scores[k + 1] >= 0.2 for k in range(len(scores) - 1)), "top-k scores are not well separated: %r" % scores
ue = [l.strip() for l in open(sys.argv[3]) if l.strip()]
uq = [l.strip() for l in open(sys.argv[4]) if l.strip()]
assert ue == uq and len(ue) == 5, "upserted (derived) ids differ: %r vs %r" % (ue, uq)
print("seam: embedded and Qdrant return the same top-3 derived ids %s with scores within %g" % ([i for i, _ in emb], EPS))
PY

echo "$ME: PASS (Qdrant $QDRANT_VERSION: embedded and Qdrant legs both govern upsert/search/refusal/restart, and agree on the top-3 ids and scores)"
