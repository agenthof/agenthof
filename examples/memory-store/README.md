# memory-store

A reference MCP server that gives a governed agent a durable vector memory. It
speaks MCP over stdio and exposes two tools:

- `memory_upsert` — store a text chunk with its embedding vector and JSON
  metadata in a collection (`collection`, `text`, `vector`, `metadata`, and an
  optional stable `id`). The stored and returned id is always a derived UUID:
  a deterministic UUIDv5 of the collection and your `id` when you pass one, so
  re-indexing the same chunk overwrites it, otherwise a random UUID. Your
  original `id` is not returned.
- `memory_search` — return the `k` stored chunks nearest to a query vector
  (`collection`, `vector`, `k`), each as `{id, score, text, metadata}` (`id`
  being the derived UUID above).

It is a **reference payload**, not a product. A production operator brings their
own vector-store MCP server. The `memory_*` tool names are this server's
convention, not an Agenthof standard: Agenthof is agnostic. It governs a store
reached through the tool door; it is not one. Embeddings stay in the agent
(through the model door); the store takes a vector and never computes one.

Storage is pluggable:

- **embedded** (default) — a file-backed, brute-force cosine index. Zero
  dependencies; meant for demos and small local use, not a production ANN
  index. It is capped at 10,000 records across all collections by default.
- **qdrant** — a Qdrant instance over its REST API (collections are created as
  Cosine). This is the production path.

Both backends return the same result shape. Metadata round-trips as semantic
JSON, not byte-identical: Qdrant re-serializes it. Invalid UTF-8 in metadata is
rejected, but some valid JSON metadata still round-trips semantically and not
byte-identically: lone-surrogate `\uXXXX` escapes, very large numbers such as
`1e999`, and duplicate keys are stored verbatim by the embedded backend while
Qdrant normalizes them. Equal cosine scores are ordered by `id` on the embedded
backend and are unspecified on Qdrant. The server returns structured MCP
content only, so a client that reads only the `content` array sees an empty
payload.

## Flags

| Flag | Meaning |
| --- | --- |
| `-backend embedded\|qdrant` | storage backend (default `embedded`) |
| `-store-file` | embedded backend: path of the store file (default `memory-store.json`) |
| `-qdrant-url` | qdrant backend: base URL of the Qdrant REST API |
| `-qdrant-auth` | qdrant backend: name of the environment variable holding the Qdrant API key (empty: none) |
| `-collections` | comma-separated allowlist of collection names (empty: any) |
| `-credential-env` | name of the environment variable carrying the caller's placeholder bearer; not used for Qdrant auth |
| `-max-entries` | embedded backend: maximum records across all collections |

Diagnostics go to stderr; stdout carries only the MCP stream. Collection names
match `[A-Za-z0-9_-]{1,64}`. A `-qdrant-url` with userinfo, a query, a fragment
or a non-`http(s)` scheme is refused, and HTTP redirects are not followed.

## Governing it

The server is stdio-only, so it is fronted by `deploy/refbridge`, which exposes
it over a Unix socket that only Agenthof dials, and then declared as a tool
resource. Nothing here changes the Agenthof core.

The bridge config (`bridge.yaml`) names the command, the credential, and the
declared egress:

```yaml
socket: /run/agenthof/bridge/memory.sock   # directory 0700, separate from the gateway socket dir
command: ["/opt/memory-store/memory-store", "-backend", "embedded",
          "-store-file", "/var/lib/agenthof-memory/memory.json",
          "-credential-env", "MEMORY_TOKEN"]
credential:
  env: MEMORY_TOKEN
  materialization: env-at-spawn
env_passthrough: []   # for a keyed Qdrant, also list the -qdrant-auth variable here
egress:
  allow: []          # for -backend qdrant, list the Qdrant host:port here
sessions:
  max: 4
  idle_timeout: 10m
  max_lifetime: 30m
```

The tool door config (`gateway.yaml`) declares the resource:

```yaml
tools:
  memory:
    kind: mcp
    url: unix:///run/agenthof/bridge/memory.sock
    runtime: refbridge
    credential_source: static_env
    token_env: MEMORY_TOKEN        # host-side placeholder; the agent never sees it
    read_only_tools: [memory_search]
```

`runtime: refbridge` makes the bridge attest first-hand, on every call that
returns a result, what it ran (argv, pid, environment names); the ledger
records that on the `tool_call` event.

Agents are then granted the resource per role of use:

```yaml
# an agent that may store and retrieve
tools:
  - resource: memory
    tools: ["*"]
    mode: read-write

# an agent that may only retrieve
tools:
  - resource: memory
    tools: ["*"]
    mode: read-only
```

A `read-only` grant exposes only the tools listed in `read_only_tools` — here
`memory_search`. A read-only agent that calls `memory_upsert` is refused ("tool
is not available to this run") and the refusal is recorded. The server's own
read-only hint does not decide this; the operator's list does.

Every `memory_upsert` and `memory_search` is a `tool_call` in the run's ledger.
The bridge's credential never reaches the agent, and the server never uses it
for Qdrant: Qdrant authentication comes only from the variable named by
`-qdrant-auth`, read by the server process the bridge starts. The bridge
builds that process's environment only from `env_passthrough` plus the
credential, so for a keyed Qdrant the variable named by `-qdrant-auth` must
also be listed in the bridge's `env_passthrough`; otherwise no API key is sent
and calls fail as "backend unavailable".

## Honest limits

These are properties of the design, stated so an operator can decide.

**1. macOS Seatbelt: the embedded store file is host-readable by default.**
Seatbelt's baseline allows host-wide reads. The embedded store file is
therefore readable by a contained agent with no memory grant and no `tool_call`
unless the file's directory is in the confiner's `deny_read` **and** outside
every later allow: not under `/tmp` or `/private/tmp`, any configured `paths`,
`store_root`, `spawn_root`, a workspace, or `shared_host_scratch` (do not
combine the store directory with `shared_host_scratch`). Set `deny_read` in
both the refspawn config and any standalone refexec config; nothing enforces
that for you. A natively run Qdrant's storage directory has the same property,
so on macOS the recommended configuration is Qdrant inside the podman VM, or an
embedded store in a correctly `deny_read`-protected directory. On podman the
compartment has `--network none` and mounts no path to the store, so
neither the embedded file nor Qdrant is reachable except through the door. On
macOS, `egress.allow` is declared, not enforced: the bridge runs on the host.

**2. The ledger records a bounded preview of search results.** The tool door
keeps a prefix of about 200 runes of each tool result. For `memory_search` that
is the raw result JSON, which leads with the MCP envelope, then each result's
`id` and `metadata` keys (the gateway re-serializes the decoded result with
keys in alphabetical order, so the preview order is id, metadata, score, text,
not the server's struct order). A retrieved record's text therefore usually falls
past the cut, but a record with short metadata can bring the start of
a field into the prefix. So the ledger holds a bounded preview that may include
the start of a retrieved record; it is neither "the text is logged" nor "never
logged". It is your own audit ledger, whose evidence is limited and
tamper-evident, not tamper-proof. The server's own error results are fixed
strings that carry none of the argument's bytes.

**3. Authorization is per tool, not per collection.** Any agent granted
`memory_upsert` may write any collection, and any agent granted `memory_search`
may read any. Anything written is later retrieved as text an agent may act on,
so treat write access as the sensitive grant. To isolate data, run one
bridge and one resource per set of collections, each started with its own
`-collections` list (the value is visible in the attested argv). Two memory
resources granted to one agent expose the same `memory_*` tool names, which
collide and cause the step to be refused, so grant an agent one memory
resource.

## Running it standalone

```sh
go build -o memory-store ./examples/memory-store
./memory-store -backend embedded -store-file ./memory.json   # MCP on stdio
```
