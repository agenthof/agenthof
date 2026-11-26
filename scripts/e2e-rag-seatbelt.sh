#!/usr/bin/env bash
# e2e-rag-seatbelt: prove the grounded retrieval loop end to end, every leaf run
# CONTAINED under the real macOS Seatbelt backend through `agenthof ask`.
#
# BY-JUDGMENT, real-backend test. Run it locally when warranted (after a change
# to the rag-* hub agents, the memory store, the embeddings door, the tool door,
# the ask orchestrator or the confiner); it is NEVER added to CI, like the other
# real-sandbox tiers (the standing podman/Seatbelt rule).
#
# It needs the hub agents rag-ingest, rag-retrieve and rag-research (and
# router-chat, the classifier) at HUB_DIR, so its GREEN RUN HAPPENS AFTER THE HUB
# EXISTS. Until then the script cannot pass; it is authored to the contract
# below and syntax-checked only.
#
# The cast. Four signed hub agents are built from the hub checkout with the
# hub's reproducible recipe and enrolled from their SIGNED cards exactly as
# published (trusted_signers = the published curator key). The refspawn
# supervisor maps each to its freshly built binary and runs it hash-bound under
# sandbox-exec. The trusted orchestrator drives every leaf via `agenthof ask`
# (the shared spawn path) — never a bare spawn directive. The fakes: the model
# and embeddings provider is scripts/fake-openai-provider.py (deterministic
# /v1/embeddings that LOGS every input text); the corpus is examples/fake-drive-mcp
# notes note-3 "Entitlements sync", note-4 "Token handling sync" (JWT) and note-5
# "Offsite logistics sync" (the distractor), all dated; the store is
# examples/memory-store (embedded). Both MCP servers sit behind refbridge on the
# host; the store directory is read-denied to every compartment.
#
# Contract assumptions about the hub agents (the names this script is written
# to): gateway resources `drive` and `memory`; models `router` (classifier),
# `chat` (generation) and `embed` (the embedding route); each agent enrolls
# under its directory name with role = workflow = that name; the orchestrator's
# menu is router-chat first (the classifier), then rag-ingest, rag-retrieve,
# rag-research, in that order (the fake classifier picks by menu number).
# The fake provider runs WITHOUT a tool script, so the proof also assumes the
# retrieve and research agents (a) retrieve CODE-DRIVEN (deterministic calls,
# never model-chosen tool calls) and (b) put the retrieved passages in a
# NON-SYSTEM message of one generation request. An agent that violates either
# fails the grounding proof loudly, by design.
#
# Asserts:
#   (ingest)    `ask` runs rag-ingest, which queries Drive for "sync" (note-3/4/5),
#               reads each note, parses the date from its "Meeting notes - <date>"
#               header, chunks, embeds each chunk and memory_upserts it with stable
#               id "<driveDocId>#<chunkIndex>" and {source, chunk_index, date}. The
#               artifact is "indexed N chunks (M undated)" with M=0; N is checked
#               against the store, the ledger and the provider's embeddings log;
#               without --yes the write is refused (the confirm gate);
#   (idempotent) a second ingest leaves the identical id SET and count; a search
#               with k>=N returns all N (N<=64, every chunk <=16384 B);
#   (falsifier 1) retrieve BEFORE ingest, on an empty store: no note text reaches
#               the provider, in a generation request or an embedding input;
#   (retrieve)  `ask` with the MULTI-WORD query "entitlement revocation" (note-3);
#               operator-stamped grounded; the receipt says so;
#   (research)  `ask` with "JWT verification" (note-4); operator-stamped mixed;
#   (GROUNDING PROOF) the planted note-3 sentence is in the generation request
#               the fake provider LOGGED (a non-system message), is in NO system
#               prompt and in no canned reply — so the answer's grounding is the
#               retrieval, not the prompt; likewise note-4 for research;
#   (falsifier 2) with note-5 indexed and fewer than N passages returned, the
#               distractor text is ABSENT from the generation request, and a
#               direct k<N search ranks it out of the top k;
#   (containment) every leaf spawn records the seatbelt tier, the host-program
#               hash this script computed itself, and a compartment named for it;
#               the gateway key and the store token reach no ledger or artifact.
#
# Environment: HUB_DIR = a checkout of the agents hub (required; the script
# skips cleanly when unset, off macOS, without /usr/bin/sandbox-exec, or on a
# toolchain that does not reproduce the cards' pinned hashes). KEEP=1 leaves the
# scratch directories for inspection. The hub pins go1.27.4 for its reproducible
# build; keep the version below in sync with it. Requires go, curl, python3 and
# pgrep. Run from the repo root (or via `make acceptance-rag HUB_DIR=<hub>`).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ -z "${HUB_DIR:-}" ]; then
	echo "e2e-rag-seatbelt: SKIP — set HUB_DIR to an agents hub checkout"
	exit 0
fi
if [ "$(uname)" != Darwin ] || [ ! -x /usr/bin/sandbox-exec ]; then
	echo "e2e-rag-seatbelt: SKIP — macOS with /usr/bin/sandbox-exec is required"
	exit 0
fi
for tool in go curl python3 pgrep; do
	command -v "$tool" >/dev/null 2>&1 || { echo "e2e-rag-seatbelt: FAIL — $tool is required"; exit 1; }
done
AGENTS="router-chat rag-ingest rag-retrieve rag-research"
[ -f "$HUB_DIR/scripts/build.sh" ] || { echo "e2e-rag-seatbelt: FAIL — HUB_DIR is not an agents hub checkout"; exit 1; }
for a in $AGENTS; do
	[ -f "$HUB_DIR/agents/$a/card.json" ] || { echo "e2e-rag-seatbelt: FAIL — the hub has no agents/$a/card.json (the rag agents must exist before this runs)"; exit 1; }
done
HUB_DIR="$(cd "$HUB_DIR" && pwd)"
HUB_GO=go1.27.4   # the hub's pinned build toolchain; keep in sync with its scripts/build.sh
if [ "$(go env GOVERSION)" != "$HUB_GO" ]; then
	echo "e2e-rag-seatbelt: SKIP — the hub's pinned hashes reproduce only on $HUB_GO (found $(go env GOVERSION)); put $HUB_GO first on PATH"
	exit 0
fi

SOCK_DIR="$(mktemp -d /tmp/rg.XXXXXX)"
SUP_DIR="$(mktemp -d /tmp/rg.XXXXXX)"
SPAWN_ROOT="$(mktemp -d /tmp/rg.XXXXXX)"
DRIVE_DIR="$(mktemp -d /tmp/rgd.XXXXXX)"  # refbridge socket dir for the drive MCP (0700, separate)
MEM_DIR="$(mktemp -d /tmp/rgm.XXXXXX)"    # refbridge socket dir for the memory MCP (0700, separate)
WORK="$(mktemp -d /tmp/rg.XXXXXX)"
# The store directory must be OUTSIDE /tmp, store_root and every workspace and
# is read-denied below: Seatbelt's baseline allows host-wide reads, so an
# undenied store file is readable by a compartment with no grant and no tool_call.
STORE_DIR="$(cd -P "$(mktemp -d /var/tmp/rgs.XXXXXX)" && pwd -P)"
chmod 0700 "$DRIVE_DIR" "$MEM_DIR" "$STORE_DIR"
STORE_FILE="$STORE_DIR/memory.json"
STORE_ROOT="$WORK/stores"
PID_DIR="$WORK/pids"
PIDS=()
PROVIDER_PID=""
cleanup() {
	[ -z "$PROVIDER_PID" ] || { kill "$PROVIDER_PID" >/dev/null 2>&1 || true; wait "$PROVIDER_PID" >/dev/null 2>&1 || true; }
	for p in ${PIDS[@]+"${PIDS[@]}"}; do
		kill "$p" >/dev/null 2>&1 || true
		wait "$p" >/dev/null 2>&1 || true
	done
	if [ "${KEEP:-0}" = 1 ]; then
		echo "e2e-rag-seatbelt: KEEP=1 — left $WORK (logs, ledgers under control/) and $STORE_DIR (the store); socket dirs $SOCK_DIR $SUP_DIR $SPAWN_ROOT $DRIVE_DIR $MEM_DIR" >&2
		return 0
	fi
	rm -rf "$SOCK_DIR" "$SUP_DIR" "$SPAWN_ROOT" "$DRIVE_DIR" "$MEM_DIR" "$STORE_DIR" "$WORK"
}
trap cleanup EXIT
fail() {
	echo "e2e-rag-seatbelt: FAIL — $*"
	for f in refspawn.err drive-bridge.err mem-bridge.err agent.err ask.err; do
		[ -f "$WORK/$f" ] && { echo "--- $f (tail)"; tail -n 40 "$WORK/$f"; } >&2
	done
	exit 1
}
unset AGENTHOF_TOKEN || true
# shellcheck source=scripts/acceptance-lib.sh
. "$ROOT/scripts/acceptance-lib.sh"   # field, count
# shellcheck source=scripts/enroll-lib.sh
. "$ROOT/scripts/enroll-lib.sh"       # enroll_agent, enroll_allow_spawn, ran_of

CURATOR_KID=f07e492a38568409cbcb459b1feac8b70e08eec00149ac1981b4f9c053412404
CURATOR_KEY=k2troapQ5SHzGpMeckKzHBUNcI517qZmiX/bw9Bl05o=
sha_of() { printf 'sha256:%s' "$(shasum -a 256 "$1" | awk '{print $1}')"; }

# Phrases planted in the committed sample notes (examples/fake-drive-mcp). Each
# is checked against the source below, so a reworded note fails here loudly.
P_ENT="takes effect on the next run"                                    # note-3, the entitlements note
P_JWT="accepted after its signature, issuer and expiry are verified"    # note-4, the token note
P_OFF="vegetarian lunch options"                                        # note-5, the distractor
for p in "$P_ENT" "$P_JWT" "$P_OFF"; do
	[ "$(grep -cF -- "$p" examples/fake-drive-mcp/main.go)" = 1 ] || fail "the planted phrase \"$p\" is not in exactly one fake-drive note"
done

# Build everything BEFORE anything starts.
go build -o "$WORK/agenthof" ./cmd/agenthof
go build -o "$WORK/refexec" ./deploy/refexec
go build -o "$WORK/refspawn" ./deploy/refspawn
go build -o "$WORK/refbridge" ./deploy/refbridge
go build -o "$WORK/memory-store" ./examples/memory-store
go build -o "$WORK/fake-drive-mcp" ./examples/fake-drive-mcp
go build -o "$WORK/echo-agent" ./examples/echo-agent
for a in $AGENTS; do
	BUILT="$("$HUB_DIR/scripts/build.sh" "$a" darwin arm64 "$WORK/$a")" || fail "the hub build of $a failed"
	HASH="$(sha_of "$WORK/$a")"
	[ "$BUILT" = "$HASH" ] || fail "the hub build of $a reported $BUILT but the bytes hash to $HASH"
	if ! grep -q "$HASH" "$HUB_DIR/agents/$a/card.json"; then
		echo "e2e-rag-seatbelt: SKIP — this $HUB_GO build does not reproduce $a's pinned darwin/arm64 hash ($HASH)"
		exit 0
	fi
done
hash_of() { sha_of "$WORK/$1"; }

# --- the checks that read provider logs, the store and the MCP stream. One
# Python file, one subcommand per assertion; each exits non-zero with a reason.
cat >"$WORK/rag_check.py" <<'PY'
import json, re, subprocess, sys, urllib.request

DATES = {"note-3": "2026-09-14", "note-4": "2026-09-21", "note-5": "2026-09-28"}
MAX_CHUNKS, MAX_TEXT = 64, 16384


def rows(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def is_chat(r):
    return r.get("path") == "/v1/chat/completions"


def generation_rows(path):
    # The classifier is told apart by MODEL (router), never by order.
    return [r for r in rows(path) if is_chat(r) and r.get("model") != "router"]


def system_text(r):
    return json.dumps([m for m in (r.get("messages") or []) if isinstance(m, dict) and m.get("role") == "system"])


def user_side_text(r):
    return json.dumps([m for m in (r.get("messages") or []) if not (isinstance(m, dict) and m.get("role") == "system")])


def load_store(path):
    doc = json.load(open(path, encoding="utf-8"))
    cols = doc.get("collections") or {}
    assert len(cols) == 1, "want exactly one collection, got %r" % sorted(cols)
    name = next(iter(cols))
    return name, cols[name].get("records") or []


def cmd_store_report(store, idfile, *phrases):
    name, recs = load_store(store)
    n = len(recs)
    assert 1 <= n <= MAX_CHUNKS, "N=%d outside 1..%d" % (n, MAX_CHUNKS)
    seen, per_doc = set(), {}
    for r in recs:
        m = re.fullmatch(r"(note-[345])#(\d+)", r.get("caller_id", ""))
        assert m, "record id %r is not <driveDocId>#<chunkIndex>" % r.get("caller_id")
        doc, idx = m.group(1), int(m.group(2))
        assert r["caller_id"] not in seen, "duplicate id " + r["caller_id"]
        seen.add(r["caller_id"])
        per_doc.setdefault(doc, []).append(idx)
        assert 0 < len(r["text"].encode()) <= MAX_TEXT, "chunk %s is empty or over %d B" % (r["caller_id"], MAX_TEXT)
        meta = json.loads(r.get("meta") or "{}")
        assert meta.get("source"), "chunk %s has no source" % r["caller_id"]
        assert str(meta.get("chunk_index")) == str(idx), "chunk %s: chunk_index %r" % (r["caller_id"], meta.get("chunk_index"))
        assert meta.get("date") == DATES[doc], "chunk %s: date %r, want %s (all three notes are dated, so M=0)" % (r["caller_id"], meta.get("date"), DATES[doc])
    assert sorted(per_doc) == sorted(DATES), "indexed docs %r, want %r" % (sorted(per_doc), sorted(DATES))
    for doc, idxs in per_doc.items():
        assert sorted(idxs) == list(range(len(idxs))), "%s chunk indexes %r are not 0..n-1" % (doc, sorted(idxs))
    # Each proof phrase must be stored INTACT in some chunk; otherwise an
    # absence check on it would pass because it was never stored whole.
    for ph in phrases:
        assert any(ph in r["text"] for r in recs), "the proof phrase %r is in no stored chunk intact (the chunker split it)" % ph
    with open(idfile, "w") as f:
        json.dump(sorted([r["id"], r["caller_id"]] for r in recs), f)
    print(n)


def cmd_store_empty(store):
    try:
        doc = json.load(open(store, encoding="utf-8"))
    except FileNotFoundError:
        return
    total = sum(len(c.get("records") or []) for c in (doc.get("collections") or {}).values())
    assert total == 0, "the store holds %d records, want none" % total


def cmd_same_ids(store, idfile):
    _, recs = load_store(store)
    now = sorted([r["id"], r["caller_id"]] for r in recs)
    before = json.load(open(idfile))
    assert now == before, "id set changed across ingests: %d before, %d after" % (len(before), len(now))
    print(len(now))


def cmd_emb_covers(log, store):
    _, recs = load_store(store)
    inputs = []
    for r in rows(log):
        if r.get("path") == "/v1/embeddings":
            raw = r.get("input")
            inputs += raw if isinstance(raw, list) else [raw]
    missing = [r["caller_id"] for r in recs if r["text"] not in inputs]
    assert not missing, "chunks never embedded through the provider: %r" % missing
    assert len(inputs) >= len(recs), "%d embedding inputs for %d chunks" % (len(inputs), len(recs))


def cmd_no_note_text(log, *phrases):
    for r in rows(log):
        blob = json.dumps(r)
        for p in phrases:
            assert p not in blob, "note text %r reached the provider (%s)" % (p, r.get("path"))


def cmd_embedded_query(log, query):
    for r in rows(log):
        if r.get("path") == "/v1/embeddings":
            raw = r.get("input")
            if query in (raw if isinstance(raw, list) else [raw]):
                return
    raise AssertionError("the query %r was never embedded through the provider" % query)


def cmd_prove(log, planted, *absent):
    gens = generation_rows(log)
    assert gens, "no generation request reached the provider"
    assert any(planted in user_side_text(g) for g in gens), "the planted note text %r is in no generation request" % planted
    for r in rows(log):
        if is_chat(r):
            assert planted not in system_text(r), "the planted note text is in a system prompt: the prompt, not the retrieval, carried it"
    for g in gens:
        for p in absent:
            assert p not in json.dumps(g), "text %r that must be absent is in the generation request" % p


def cmd_direct_search(snapshot, store_bin, port, query):
    name, recs = load_store(snapshot)
    n = len(recs)
    by_id = {r["id"]: r["caller_id"] for r in recs}
    req = urllib.request.Request("http://127.0.0.1:%s/v1/embeddings" % port,
                                 data=json.dumps({"model": "embed", "input": query}).encode(),
                                 headers={"Authorization": "Bearer dummy", "Content-Type": "application/json"})
    vec = json.load(urllib.request.urlopen(req, timeout=10))["data"][0]["embedding"]
    p = subprocess.Popen([store_bin, "-backend", "embedded", "-store-file", snapshot, "-credential-env", "MEMORY_TOKEN"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    seq = [0]

    def rpc(method, params, notify=False):
        msg = {"jsonrpc": "2.0", "method": method, "params": params}
        if not notify:
            seq[0] += 1
            msg["id"] = seq[0]
        p.stdin.write(json.dumps(msg) + "\n")
        p.stdin.flush()
        while not notify:
            line = p.stdout.readline()
            assert line, "memory-store closed its stream"
            resp = json.loads(line)
            if resp.get("id") == seq[0]:
                assert "error" not in resp, resp["error"]
                return resp["result"]

    def search(k):
        res = rpc("tools/call", {"name": "memory_search", "arguments": {"collection": name, "vector": vec, "k": k}})
        body = res.get("structuredContent")
        if body is None:
            body = json.loads(res["content"][0]["text"])
        if isinstance(body, dict):
            body = next(v for v in body.values() if isinstance(v, list))
        return [by_id[h["id"]] for h in body]

    try:
        rpc("initialize", {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "rag-check", "version": "0"}})
        rpc("notifications/initialized", {}, notify=True)
        full = search(min(MAX_CHUNKS, max(n, 1)))
        assert len(full) == n, "k>=N returned %d of N=%d" % (len(full), n)
        assert len(set(full)) == n, "k>=N returned duplicates"
        k = max(1, n - 1)
        top = search(k)
        assert len(top) == k < n, "k<N search returned %d" % len(top)
        assert top[0].startswith("note-3#"), "the entitlement query's best chunk is %s, not note-3" % top[0]
        small = search(2)
        assert not any(c.startswith("note-5#") for c in small), "the distractor ranks in the top 2: %r" % small
        notes5 = [c for c in by_id.values() if c.startswith("note-5#")]
        assert notes5, "no distractor chunk is indexed, so its absence proves nothing"
    finally:
        p.stdin.close()
        p.wait(timeout=10)
    print("k>=N returned %d; top-2 %r" % (n, small))


if __name__ == "__main__":
    try:
        globals()["cmd_" + sys.argv[1].replace("-", "_")](*sys.argv[2:])
    except AssertionError as e:
        print("check %s: %s" % (sys.argv[1], e), file=sys.stderr)
        sys.exit(1)
PY
check() { python3 "$WORK/rag_check.py" "$@"; }

# --- the fake provider (chat + embeddings), restarted per phase so each phase
# has its own request log and its classifier pick. The classifier model answers
# the numbered menu with PICK; the chat model answers with a fixed, note-free
# canned reply, so any note text found in a generation REQUEST came from retrieval.
PROVIDER_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
NONCE="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
CANNED="answered:$NONCE"
for p in "$P_ENT" "$P_JWT" "$P_OFF"; do
	case "$CANNED" in *"$p"*) fail "the canned reply carries note text" ;; esac
done
start_provider() { # $1 = classifier pick (menu number), $2 = request log
	if [ -n "$PROVIDER_PID" ]; then
		kill "$PROVIDER_PID" >/dev/null 2>&1 || true
		wait "$PROVIDER_PID" >/dev/null 2>&1 || true
	fi
	: >"$2"
	python3 scripts/fake-openai-provider.py --bind "127.0.0.1:$PROVIDER_PORT" --reply "$CANNED" \
		--reply-for "router=$1" --log "$2" >/dev/null 2>>"$WORK/provider.err" &
	PROVIDER_PID=$!
	for i in $(seq 1 60); do
		curl -s -o /dev/null "http://127.0.0.1:$PROVIDER_PORT/" && return 0
		[ "$i" = 60 ] && fail "the fake provider never came up"
		sleep 0.2
	done
}
export AGENTHOF_GATEWAY_KEY="host-side-dummy-key-$NONCE" MEMORY_TOKEN="memory-secret-$NONCE" DRIVE_BRIDGE_BEARER="drive-secret-$NONCE"

# --- the governed MCP paths on the HOST: refbridge -> fake-drive-mcp, and
# refbridge -> memory-store (embedded).
for which in drive memory; do
	case "$which" in
	drive) dir="$DRIVE_DIR"; cmd="[\"$WORK/fake-drive-mcp\"]"; env=DRIVE_BRIDGE_BEARER ;;
	*) dir="$MEM_DIR"; cmd="[\"$WORK/memory-store\", \"-backend\", \"embedded\", \"-store-file\", \"$STORE_FILE\", \"-credential-env\", \"MEMORY_TOKEN\"]"; env=MEMORY_TOKEN ;;
	esac
	cat >"$WORK/$which-bridge.yaml" <<EOC
socket: $dir/$which.sock
command: $cmd
credential:
  env: $env
  materialization: env-at-spawn
env_passthrough: []
egress:
  allow: []
sessions:
  max: 4
  idle_timeout: 10m
  max_lifetime: 30m
EOC
	"$WORK/refbridge" -config "$WORK/$which-bridge.yaml" 2>>"$WORK/$which-bridge.err" &
	PIDS+=($!)
done

# The working config directory and the control root are both read-denied to
# every compartment, as are the store directory; each must exist before refspawn
# starts (Seatbelt resolves the deny to a real path).
CFG="$WORK/config"
mkdir -p "$CFG/agents" "$CFG/workflows" "$CFG/roles"
CFG_REAL="$(cd "$CFG" && pwd -P)"
CTL_DIR="$WORK/control"
mkdir -p "$CTL_DIR"
CTL_REAL="$(cd "$CTL_DIR" && pwd -P)"
(umask 077 && mkdir -p "$STORE_ROOT" "$PID_DIR")
cat >"$WORK/refspawn.yaml" <<EOC
confiner: seatbelt
socket: $SUP_DIR/refspawn.sock
spawn_root: $SPAWN_ROOT
store_root: $STORE_ROOT
pid_dir: $PID_DIR
deny_config_read: $CFG_REAL
deny_read:
  - $CTL_REAL
  - $STORE_DIR
images:
  router-chat: $WORK/router-chat
  rag-ingest: $WORK/rag-ingest
  rag-retrieve: $WORK/rag-retrieve
  rag-research: $WORK/rag-research
timeout: 5m
ready_timeout: 60s
limits:
  memory: 256m
  cpus: "1"
  pids: 64
max_compartments: 3
refexec:
  command: [$WORK/refexec]
  timeout: 2m
  limits:
    memory: 256m
    cpus: "1"
    pids: 64
  max_compartments: 2
  env_allow: []
EOC
"$WORK/refspawn" -config "$WORK/refspawn.yaml" 2>>"$WORK/refspawn.err" &
PIDS+=($!)

# The orchestrator's own endpoint: a host process that never runs a step.
mkdir -p "$WORK/lead-ws"
"$WORK/echo-agent" -socket "$SOCK_DIR/agent.sock" -workspace "$WORK/lead-ws" 2>"$WORK/agent.err" &
PIDS+=($!)
for i in $(seq 1 60); do
	[ -S "$SUP_DIR/refspawn.sock" ] && [ -S "$SOCK_DIR/agent.sock" ] && [ -S "$DRIVE_DIR/drive.sock" ] && [ -S "$MEM_DIR/memory.sock" ] && break
	[ "$i" = 60 ] && fail "the supervisor, agent or bridge sockets never appeared"
	sleep 0.5
done
start_provider 1 "$WORK/boot.jsonl"

# --- the installed configuration: three models (classifier, generation, the
# embedding route) all on the one fake provider ORIGIN, two governed MCP tools.
cat >"$CFG/gateway.yaml" <<EOC
refbox_socket_dir: $SOCK_DIR
spawn_supervisor: unix://$SUP_DIR/refspawn.sock
spawn:
  max_depth: 3
  max_parallel: 2
  max_total_spawns: 8
step_timeout: 3m
models:
  router:
    endpoint: http://127.0.0.1:$PROVIDER_PORT
    model: router
    api_key_env: AGENTHOF_GATEWAY_KEY
  chat:
    endpoint: http://127.0.0.1:$PROVIDER_PORT
    model: chat
    api_key_env: AGENTHOF_GATEWAY_KEY
  embed:
    endpoint: http://127.0.0.1:$PROVIDER_PORT
    model: embed
    api_key_env: AGENTHOF_GATEWAY_KEY
defaults:
  model: chat
tools:
  drive:
    kind: mcp
    url: unix://$DRIVE_DIR/drive.sock
    runtime: refbridge
    credential_source: static_env
    token_env: DRIVE_BRIDGE_BEARER
    read_only_tools: [search, readGoogleDoc]
  memory:
    kind: mcp
    url: unix://$MEM_DIR/memory.sock
    runtime: refbridge
    credential_source: static_env
    token_env: MEMORY_TOKEN
    read_only_tools: [memory_search]
trusted_signers:
  - {kid: $CURATOR_KID, key: $CURATOR_KEY}
EOC
cat >"$CFG/agents/orchestrator.yaml" <<EOC
name: orchestrator
description: routes a request to the agent that answers it
model: chat
instruction: Route.
output: output
execution: fronted
endpoint: unix://$SOCK_DIR/agent.sock
may_spawn:
EOC
printf 'name: ask\ndescription: ask\nsteps:\n  - name: ask\n    agent: orchestrator\n' >"$CFG/workflows/ask.yaml"
printf 'name: orchestrator\ndescription: Runs ask\nworkflows: [ask]\nallowed_groups: ["spawn-users"]\n' >"$CFG/roles/orchestrator.yaml"
cat >"$CFG/agents/lead.yaml" <<EOC
name: lead
description: the enrolling role's host agent
model: chat
instruction: Run the script.
output: output
execution: fronted
endpoint: unix://$SOCK_DIR/agent.sock
may_spawn:
EOC
printf 'name: lead-wf\ndescription: lead\nsteps:\n  - name: lead\n    agent: lead\n' >"$CFG/workflows/lead-wf.yaml"
cat >"$CFG/roles/lead.yaml" <<EOC
name: lead
description: Enrolls agents
workflows: [lead-wf]
allowed_groups: ["spawn-users"]
control: [apply, enroll]
EOC
ARGS=(--config "$CFG" --control-log "$CTL_DIR/control.jsonl" --as ci --groups spawn-users)
"$WORK/agenthof" apply "${ARGS[@]}" >"$WORK/apply.out" 2>&1 || { cat "$WORK/apply.out"; fail "apply of the base config failed"; }

# Enroll the four hub cards exactly as published, then the operator's own edits:
# the grounding stamps (rag-retrieve grounded, rag-research mixed; rag-ingest is
# left unstamped — it makes no chat call) and the orchestrator's menu, in order.
# shellcheck disable=SC2034  # read by enroll_agent in enroll-lib.sh
ENROLL_ARGS=("${ARGS[@]}")
# shellcheck disable=SC2034  # read by enroll_agent in enroll-lib.sh
AGENTHOF="$WORK/agenthof"
for a in $AGENTS; do
	enroll_agent "$HUB_DIR/agents/$a/card.json" "$a" "$CFG"
	printf '%s\n' "$ENROLL_OUT" | grep -q "seatbelt (program \"$a\"" || { echo "$ENROLL_OUT"; fail "enroll of $a did not offer the program mapping for the seatbelt tier"; }
	grep -q "$(hash_of "$a")" "$CFG/agents/$a.yaml" || fail "the enrolled $a does not record the consented hash"
done
stamp() { # $1 = agent, $2 = grounding
	! grep -q '^grounding:' "$CFG/agents/$1.yaml" || fail "the card already sets grounding for $1; the operator stamp would duplicate it"
	printf 'grounding: %s\n' "$2" >>"$CFG/agents/$1.yaml"
}
stamp rag-retrieve grounded
stamp rag-research mixed
for a in router-chat rag-ingest rag-retrieve rag-research; do enroll_allow_spawn "$CFG/agents/orchestrator.yaml" "$a"; done
"$WORK/agenthof" apply "${ARGS[@]}" >"$WORK/apply.out" 2>&1 || { cat "$WORK/apply.out"; fail "apply of the enrolled agents failed"; }

ledger() { echo "$CTL_DIR/runs/$1.jsonl"; }
audit_of() { "$WORK/agenthof" audit "$1" --log-dir "$CTL_DIR/runs" --control-log "$CTL_DIR/control.jsonl"; }
# ask PROMPT [extra flags...]: runs `agenthof ask` (flags go BEFORE the prompt).
# Sets ASK_OUT (stdout), ASK_RC and leaves the receipt on $WORK/ask.err; SUP_AT
# marks where this ask's supervisor lines start.
ask() {
	local prompt="$1"
	shift
	SUP_AT="$(wc -l <"$WORK/refspawn.err" | tr -d ' ')"
	ASK_RC=0
	# Feed stdin from an empty pipe, not /dev/null: ask detects an interactive
	# terminal as a character device, and /dev/null is a character device, so
	# </dev/null takes the prompt-then-EOF branch. A pipe is not a character
	# device, so ask takes the non-interactive branch and the confirm gate
	# reports the "re-run with --yes" refusal this test asserts. (Note: real
	# cron/systemd/nohup jobs DO pass /dev/null as stdin and hit the former
	# branch; it still fails closed and names --yes, so the engine is left
	# as-is. That heuristic is a separate, tracked limitation.)
	ASK_OUT="$(printf '' | "$WORK/agenthof" ask "$@" "${ARGS[@]}" --log-dir "$CTL_DIR/runs" --artifact-dir "$CTL_DIR/artifacts" "$prompt" 2>"$WORK/ask.err")" || ASK_RC=$?
	tail -n "+$((SUP_AT + 1))" "$WORK/refspawn.err" >"$WORK/sup-tail.err"
	cat "$WORK/ask.err"
}
# ran_ok AGENT: the ask just run picked AGENT/AGENT and its leaf ran contained:
# sets ASK_RUN, LEAF (the leaf's run id) and LEAF_LEDGER.
ran_ok() {
	local a="$1" c
	[ "$ASK_RC" = 0 ] || fail "ask for $a exited $ASK_RC"
	ASK_RUN="$(sed -n "s/^ask \(r-[a-f0-9]*\): picked $a\/$a\$/\1/p" "$WORK/ask.err")"
	[ -n "$ASK_RUN" ] || fail "ask did not report picking $a/$a (the menu order or the classifier pick is wrong)"
	local al
	al="$(ledger "$ASK_RUN")"
	[ "$(count "$al" spawn succeeded)" = 2 ] || fail "$a: expected two succeeded spawns (the classifier, the leaf) on the ask ledger"
	[ "$(field "$al" workflow_finished status)" = succeeded ] || fail "$a: the ask run did not finish succeeded"
	[ "$(ran_of "$al" "$a")" = "host-program $(hash_of "$a")" ] || { ran_of "$al" "$a"; fail "$a: the spawn's child_artifact is not the host-program hash computed here"; }
	[ "$(field "$al" spawn child_confiner succeeded | sort -u)" = seatbelt ] || fail "$a: a spawn does not record the seatbelt tier"
	for c in $(field "$al" spawn child_run_id succeeded); do
		grep -q "compartment started.*child=$c.*compartment=agenthof-spawn-$c-" "$WORK/sup-tail.err" || fail "$a: child $c did not run in a compartment named for it"
		# Capture, then grep: a piped `grep -q` closes the pipe on its first
		# match, and under `set -o pipefail` the SIGPIPE'd audit process can make
		# the pipeline fail even though the text matched. Dump the output on a
		# real miss so the failure is legible.
		local aout
		aout="$(audit_of "$c" 2>&1)"
		printf '%s\n' "$aout" | grep -q "ledger integrity: verified" || { echo "--- audit $c ---"; printf '%s\n' "$aout"; fail "$a: child $c ledger not verified"; }
	done
	grep -q "compartment started.*-$a" "$WORK/sup-tail.err" || fail "$a did not run in a compartment"
	LEAF="$(field "$al" spawn child_run_id succeeded | tail -n 1)"
	LEAF_LEDGER="$(ledger "$LEAF")"
	grep -Eq "$a/$a +run r-[a-f0-9]+: containment tier seatbelt" "$WORK/ask.err" || fail "$a: the receipt does not name the seatbelt tier on the leaf's line"
	grep -Eq "ledger $ASK_RUN: chain verified, completeness complete" "$WORK/ask.err" || fail "$a: the ask run's own ledger does not report completeness complete"
	aout="$(audit_of "$ASK_RUN" 2>&1)"
	printf '%s\n' "$aout" | grep -q "ledger completeness: complete (2 door call(s) accounted)" || { echo "--- audit $ASK_RUN ---"; printf '%s\n' "$aout"; fail "$a: audit <ask-run> does not report completeness complete with two door calls"; }
}
tool_ok() { # LEDGER TOOL: how many succeeded tool_call events name TOOL
	python3 - "$1" "$2" <<'PY'
import json, re, sys
n = 0
want = re.compile(r"(.*[./:-]|.*__)?" + re.escape(sys.argv[2]))
for line in open(sys.argv[1]):
    if line.strip():
        e = json.loads(line)
        if e.get("type") == "tool_call" and e.get("status") == "succeeded" and want.fullmatch(str(e.get("tool", ""))):
            n += 1
print(n)
PY
}

# ---------------------------------------------------------------- confirm gate
# Ingest writes to the store (a read-write grant), so ask refuses it without
# --yes when there is no terminal to confirm on, and writes nothing.
start_provider 1 "$WORK/gate.jsonl"
ask "index my meeting notes $NONCE"
[ "$ASK_RC" != 0 ] || fail "ask ran rag-ingest without --yes and without a terminal"
grep -q "will write to your store" "$WORK/ask.err" || fail "the refusal does not say the ingest writes to the store"
grep -q "re-run with --yes" "$WORK/ask.err" || fail "the refusal does not point at --yes"
[ ! -e "$STORE_FILE" ] || fail "the refused ingest still wrote the store"
echo "confirm gate: ingest without --yes is refused with the write reason and wrote nothing — ok"

# ---------------------------------------------------- falsifier 1: empty store
# Retrieve BEFORE any ingest. Whatever the agent answers (its exit code is
# recorded, not asserted: the contract does not say how an empty store ends),
# NO note text may reach the provider — not in a generation request, not in any
# embedding input — and nothing may be stored.
start_provider 2 "$WORK/f1.jsonl"
ask "entitlement revocation" --yes
F1_RC="$ASK_RC"
if grep -Eq "panic:|fatal error:" "$WORK/ask.err" "$WORK/sup-tail.err"; then fail "falsifier 1: the empty-store retrieve crashed (panic or fatal error)"; fi
grep -q "picked rag-retrieve/rag-retrieve" "$WORK/ask.err" || fail "falsifier 1: ask did not pick rag-retrieve"
check no-note-text "$WORK/f1.jsonl" "$P_ENT" "$P_JWT" "$P_OFF" || fail "falsifier 1: note text reached the provider although the store was empty"
check embedded-query "$WORK/f1.jsonl" "entitlement revocation" || fail "falsifier 1: the retrieve agent never embedded the query, so the empty-store run proves nothing"
case "$ASK_OUT" in *"$P_ENT"* | *"$P_JWT"* | *"$P_OFF"*) fail "falsifier 1: note text appeared in the answer of an empty-store retrieve" ;; esac
check store-empty "$STORE_FILE" || fail "falsifier 1: retrieve created store content"
echo "falsifier 1: retrieve on an empty store (exit $F1_RC) carried no note text to the provider — ok"

# --------------------------------------------------------------------- ingest
start_provider 1 "$WORK/ing1.jsonl"
ask "index my meeting notes $NONCE" --yes
ran_ok rag-ingest
INGEST_LEDGER="$LEAF_LEDGER"
printf '%s\n' "$ASK_OUT" | grep -Eq '^indexed [0-9]+ chunks \(0 undated\)$' || { echo "stdout: $ASK_OUT"; fail "the ingest artifact is not exactly \"indexed N chunks (0 undated)\" (all three notes are dated, so M=0)"; }
N="$(printf '%s\n' "$ASK_OUT" | sed -n 's/^indexed \([0-9][0-9]*\) chunks (0 undated)$/\1/p')"
STORE_N="$(check store-report "$STORE_FILE" "$WORK/ids.json" "$P_ENT" "$P_JWT" "$P_OFF")" || fail "the store does not hold what the contract says (ids, metadata, dates, sizes)"
[ "$STORE_N" = "$N" ] || fail "the artifact says $N chunks but the store holds $STORE_N"
[ "$(tool_ok "$INGEST_LEDGER" memory_upsert)" = "$N" ] || fail "the ingest ledger does not show $N succeeded memory_upsert calls"
[ "$(tool_ok "$INGEST_LEDGER" readGoogleDoc)" = 3 ] || fail "the ingest ledger does not show the three notes read"
[ "$(tool_ok "$INGEST_LEDGER" search)" -ge 1 ] || fail "the ingest ledger shows no Drive search"
grep -q '"runtime_attestation":{"runtime":"refbridge"' "$INGEST_LEDGER" || fail "the ingest tool_calls carry no refbridge attestation"
check emb-covers "$WORK/ing1.jsonl" "$STORE_FILE" || fail "an ingested chunk was not embedded through the provider"
if grep -q "^  rag-ingest:" "$WORK/ask.err"; then fail "the receipt prints a provenance line for rag-ingest, which makes no chat call"; fi
echo "ingest: indexed $N chunks (0 undated) from note-3/4/5, ids <doc>#<index>, dated, embedded, contained — ok"

# ----------------------------------------------------------------- idempotency
start_provider 1 "$WORK/ing2.jsonl"
ask "index my meeting notes $NONCE" --yes
ran_ok rag-ingest
[ "$(printf '%s\n' "$ASK_OUT" | sed -n 's/^indexed \([0-9][0-9]*\) chunks (0 undated)$/\1/p')" = "$N" ] || fail "the second ingest did not index the same $N chunks"
[ "$(check same-ids "$STORE_FILE" "$WORK/ids.json")" = "$N" ] || fail "the second ingest changed the id set"
echo "idempotency: two ingests leave the identical $N-id set — ok"

# k>=N returns all N; the k<N search ranks the distractor out. A direct search
# on a SNAPSHOT of the store through a second memory-store process (the embedded
# store's flock is per operation, but the snapshot keeps the live file untouched).
start_provider 2 "$WORK/direct.jsonl"
cp "$STORE_FILE" "$WORK/snapshot.json"
SEARCH_OUT="$(check direct-search "$WORK/snapshot.json" "$WORK/memory-store" "$PROVIDER_PORT" "entitlement revocation")" || fail "the direct memory_search checks failed"
echo "search: $SEARCH_OUT — ok"

# ------------------------------------------------------ retrieve (grounded)
start_provider 2 "$WORK/ret.jsonl"
ask "entitlement revocation" --yes
ran_ok rag-retrieve
[ "$ASK_OUT" = "$CANNED" ] || { echo "stdout: $ASK_OUT"; fail "stdout is not exactly the provider's canned answer"; }
[ "$(tool_ok "$LEAF_LEDGER" memory_search)" -ge 1 ] || fail "the retrieve ledger shows no succeeded memory_search"
[ "$(tool_ok "$LEAF_LEDGER" readGoogleDoc)" = 0 ] || fail "the retrieve leaf read Drive directly; grounding must come from the store"
[ "$(tool_ok "$LEAF_LEDGER" search)" = 0 ] || fail "the retrieve leaf searched Drive directly; grounding must come from the store"
grep -q '"runtime_attestation":{"runtime":"refbridge"' "$LEAF_LEDGER" || fail "the retrieve tool_call carries no refbridge attestation"
check embedded-query "$WORK/ret.jsonl" "entitlement revocation" || fail "the query was not embedded through the provider"
grep -Fq "rag-retrieve: grounded — declared to answer from your data; retrieval observed (read-tool call ×" "$WORK/ask.err" || fail "the receipt does not report rag-retrieve as grounded with retrieval observed"
# GROUNDING PROOF + falsifier 2: the planted note-3 sentence is in the generation
# request the provider logged (non-system), in no system prompt, and the
# distractor note-5 text — indexed, but outside the top k < N — is absent.
check prove "$WORK/ret.jsonl" "$P_ENT" "$P_OFF" || fail "the grounding proof failed for the retrieve run"
echo "retrieve: grounded answer; the note-3 sentence is in the logged generation request and no system prompt, the distractor is absent — ok"

# --------------------------------------------------------- research (mixed)
start_provider 3 "$WORK/res.jsonl"
ask "JWT verification" --yes
ran_ok rag-research
[ "$ASK_OUT" = "$CANNED" ] || { echo "stdout: $ASK_OUT"; fail "research stdout is not exactly the provider's canned answer"; }
[ "$(tool_ok "$LEAF_LEDGER" memory_search)" -ge 1 ] || fail "the research ledger shows no succeeded memory_search"
[ "$(tool_ok "$LEAF_LEDGER" readGoogleDoc)" = 0 ] || fail "the research leaf read Drive directly; grounding must come from the store"
[ "$(tool_ok "$LEAF_LEDGER" search)" = 0 ] || fail "the research leaf searched Drive directly; grounding must come from the store"
grep -q '"runtime_attestation":{"runtime":"refbridge"' "$LEAF_LEDGER" || fail "the research tool_call carries no refbridge attestation"
grep -Fq "rag-research: mixed — declared to answer from your notes and the model; retrieval observed (read-tool call ×" "$WORK/ask.err" || fail "the receipt does not report rag-research as mixed with retrieval observed"
check prove "$WORK/res.jsonl" "$P_JWT" "$P_OFF" || fail "the grounding proof failed for the research run"
echo "research: mixed answer; the note-4 sentence reached the generation request through retrieval only — ok"

# -------------------------------------------------------------------- no leaks
for secret in "$AGENTHOF_GATEWAY_KEY" "$MEMORY_TOKEN" "$DRIVE_BRIDGE_BEARER"; do
	if grep -rqF -- "$secret" "$CTL_DIR/runs" "$CTL_DIR/artifacts" 2>/dev/null; then fail "a host-side credential reached a ledger or artifact"; fi
done
echo "no leak: no host-side credential reached any ledger or artifact — ok"

echo "e2e-rag-seatbelt: PASS"
