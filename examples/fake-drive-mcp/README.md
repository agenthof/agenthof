# fake-drive-mcp

A stand-in for a Google Drive MCP server, plus a guide to fronting a real one.

**What this is.** `fake-drive-mcp` is a CI test double. It is a small MCP server
over stdio that returns canned data and never contacts Google. It exposes
`search(query)`, `readGoogleDoc(documentId)` and, so that a refusal test refuses
a genuine upstream tool name rather than a strawman, `downloadFile(fileId,
localPath)`, which returns a canned string and writes nothing. At startup it
prints a SHA-256 fingerprint of one credential variable to stderr (no tool
returns it), never the value. **It is not for production.** Use it to
exercise the governance wiring below without a Google account; bring a real Drive
MCP for real documents.

Agenthof ships no Drive integration. It governs a Drive MCP you choose, reached
through the tool door. The governance is the same for any Drive MCP.

## Fronting a real Drive MCP

A Drive MCP is stdio-only, so it is fronted by `deploy/refbridge`, which exposes
it over a Unix socket that only Agenthof dials, and is then declared as a tool
resource. Nothing here changes the Agenthof core.

The bridge config (`bridge.yaml`):

```yaml
socket: /run/agenthof/bridge/drive.sock   # directory 0700, separate from the gateway socket dir
# Absolute node and absolute script, from a pre-installed, version-pinned copy.
# The path below is a placeholder. Do not use `npx`: it would fetch from the
# network on every child start, unpinned, and outside any egress control.
command: ["/usr/bin/node", "/opt/google-drive-mcp/dist/index.js"]
credential:
  env: DRIVE_BRIDGE_BEARER      # a non-empty placeholder; the MCP ignores it for Google auth
  materialization: env-at-spawn
env_passthrough:
  - GOOGLE_DRIVE_MCP_REFRESH_TOKEN
  - GOOGLE_DRIVE_MCP_CLIENT_ID
  - GOOGLE_DRIVE_MCP_CLIENT_SECRET
egress:
  allow: [oauth2.googleapis.com, www.googleapis.com, docs.googleapis.com]
sessions:
  max: 4
  idle_timeout: 10m
  max_lifetime: 30m
```

The bridge starts the MCP with a clean environment: only `env_passthrough` plus
the credential variable. All three Google variables must be set in the
bridge's own environment. A passthrough variable that is unset there is dropped
silently, and an MCP that finds no token may fall back to opening a browser for
OAuth, which is useless and wrong in a contained run. The secret travels in the
environment, never in argv: the bridge attests argv verbatim but only the
environment **names**.

The tool door config (`gateway.yaml`):

```yaml
tools:
  drive:
    kind: mcp
    url: unix:///run/agenthof/bridge/drive.sock
    runtime: refbridge
    credential_source: static_env
    token_env: DRIVE_BRIDGE_BEARER   # host-side placeholder; Agenthof never hands it to the agent
    read_only_tools: [search, readGoogleDoc]
```

The agent's grant is the **named** read-only form:

```yaml
tools:
  - resource: drive
    tools: [search, readGoogleDoc]
    mode: read-only
```

Use the named form, not `tools: ["*"]`. With names, the gateway fails the run if
a granted tool is absent from the MCP's live catalog, so a typo or a tool renamed
in a newer release fails loudly instead of quietly granting less. This is also
why you pin the MCP's version.

### How the door narrows a large tool surface

An off-the-shelf Drive MCP can expose over a hundred tools across Drive, Docs,
Sheets, Slides and Calendar, including ones that write to the host filesystem,
change sharing, or manage accounts. The door reduces that to the two read calls:

1. **The agent is shown only the granted tools.** The gateway builds the agent's
   toolbox as an intersection with the grant; it does not forward the MCP's list.
2. **A call for any other name is refused and recorded** ("tool is not
   available to this run"), whether hallucinated or injected by a poisoned
   document.
3. **A read-only grant may name only tools you listed in `read_only_tools`.** The
   registry rejects a grant that names anything else. The classification is
   yours: the upstream's own read-only hint does not decide it.
4. **The credential's scope is a floor.** Mint the token read-only (below), so a
   write that somehow reached Google is refused there too.
5. **Startup reconciliation** (the named grant, above).

The agent itself runs contained with no network, reaching Agenthof only over its
gateway socket.

### Mint the token read-only

Most Drive MCPs default to a broad scope set. Set the MCP's scope setting (for the
example below, `GOOGLE_DRIVE_MCP_SCOPES`) **when you mint the refresh token**, to
a list made only of `*.readonly` scopes: Drive read-only, plus the Docs
read-only scope for `readGoogleDoc`. Do not use a bare read/write Docs scope.
This is a consent-time setting, not a runtime knob, so it is **not** in
`env_passthrough`: the read-only property lives in the minted token. Agenthof has
no runtime check of it; read-only is an operator obligation, and you can
confirm what a token grants by inspecting an access token minted from the
refresh token with Google's `tokeninfo` endpoint (the refresh token itself is
not what that endpoint reads).

The MCP provides its own consent setup for minting the token. Agenthof builds none.

## The MCP holds your Google token: a supply-chain caveat

This is an operator obligation, not an endorsement. **Any Drive MCP you front
holds your Google token.** Vet it, pin it, and confine its egress. The door
**bounds** an untrusted MCP (a large tool surface reduced to two read calls, a
read-only grant, a contained agent); it does **not vet** it. A malicious or
compromised MCP can still misuse the token it holds.

The door bounds the **agent's** use of the MCP, not the MCP itself. The MCP is
third-party code that the bridge runs as a host process with the bridge user's
privileges, so its reach is not limited to the token's scope. Run the bridge and
the MCP in a compartment or VM, and confine the MCP's egress: otherwise a
compromised MCP can also send the token elsewhere. The project's real-backend run
follows this: on macOS it runs inside a Linux VM; on a Linux host it runs as a
host process, so use a dedicated machine or VM and confine it.

`@piotr-agier/google-drive-mcp` is one example of a Drive MCP that fits this
wiring (it takes its credentials from the three variables above). It is a
third-party, single-maintainer package, **not official and not recommended**.
The project uses a pinned copy of it only as a fixture in a local real-backend
test run (on macOS, inside a Linux VM). Whichever MCP you choose, install it
pre-built at a pinned version with a lockfile, without install scripts, and
launch it by absolute path as above. You vet and pin the MCP; Agenthof governs
access to it. The real-backend run (`scripts/e2e-drive.sh`) installs nothing: it
takes the path of your vetted install in `DRIVE_MCP_DIR`.

## Honest limits

These are properties of the design, stated so an operator can decide.

**1. Two tiers, three guarantees.**
- *Agent network:* denied on both tiers: `--network none` under rootless podman,
  and `(deny network*)` under macOS Seatbelt.
- *Credential exposure to the contained agent:* on **macOS Seatbelt** a contained
  agent can read the environment of other host processes (the bridge and the
  MCP), including credential variables, through `sysctl`. This is not a file
  read, so `deny_read` does not stop it. On podman the namespaces isolate it.
  So **real Google credentials belong on the podman tier only** (for example inside a Linux VM on a Mac); on Seatbelt use a
  placeholder credential. A credential kept in a file is **not**
  protected by default: Seatbelt allows host-wide reads, so a contained agent can
  read it unless you list its directory in the confiner's `deny_read` and keep it
  outside every later allow (for example `/tmp`, a workspace, or a shared scratch
  path). Nothing enforces that for you; it is an operator obligation. It
  covers the MCP's own at-rest files too: the MCP's consent setup writes
  `~/.config/google-drive-mcp/tokens.json` and `gcp-oauth.keys.json`, which fall
  under the same obligation.
- *The MCP's own egress:* `egress.allow` is declared, and enforced only by an
  operator network that restricts the bridge's process; on the host it is
  validated, not enforced. The MCP holds the token and could in principle send it
  elsewhere. The agent is contained regardless; the mitigation for the MCP is
  confining its egress, not trusting it.

**2. The ledger records a bounded preview of results.** The tool door keeps a
prefix of up to 200 runes of each result. The start of a retrieved document's text,
and document names, may therefore land in your audit ledger. Treat the ledger as
holding personal data. It is your own ledger, and its evidence is limited and
tamper-evident, not tamper-proof.

**3. Upstream error text is recorded, so a server's errors may carry your arguments.** With
a server you do not control, up to 200 runes of a failed call's error text are
recorded verbatim, and such servers echo ids, queries and Google error bodies into
it. The property to verify against a real backend is that no Google **token**
appears there. Unlike a server that returns fixed error strings (such as the
`memory-store` reference), a third-party MCP gives no guarantee that argument
bytes stay out of the ledger. The door does not redact results: it
forwards the MCP's full result to the agent, so "no token in a result" holds only
because the MCP does not emit one.

**4. Capability is the MCP's, not least-privileged.** The read tools expose any
file the read-only token can see, read by id. Authorization is per tool, not per
document. Mitigation, with no code: provision a **dedicated Google account** with
only the folder you want read shared to it, so the token's visibility is the
constraint. This is a single provisioned user token, read-only, for one user.
Retrieved document text is untrusted input: a document can carry prompt injection.

**5. The refresh token's durability is Google's.** A refresh token lasts while the
OAuth app is Internal or published, but can be revoked: re-consent beyond the
per-client token limit, long inactivity, or administrator revocation. Expect to
re-mint it occasionally.

## The production target: the official Google Drive MCP

Google hosts a Drive MCP at `drivemcp.googleapis.com` (remote HTTP, Developer
Preview at the time of writing). It is the intended production target once
Agenthof can run a per-user OAuth consent flow for a remote resource (distinct
from the token exchange that ships today) and the service leaves preview. It would be
declared as a remote tool resource (`url: https://...`), with **no refbridge**.
Being remote, it carries weaker provenance: there is no first-hand runtime
attestation of what ran, because Agenthof's bridge is not the party running it.
It trades the single-maintainer package risk above for that. It is not wired
today.

## Running the fake

```sh
go build -o fake-drive-mcp ./examples/fake-drive-mcp
./fake-drive-mcp   # MCP on stdio
```

The hermetic acceptance run `scripts/e2e-drive-local.sh` fronts it through
`refbridge` and the tool door with the named read-only grant shown above.
