# The life of an enrollment

`agenthof enroll` brings something under governance without hand-editing YAML.
It has two journeys, covered in turn below: an **agent** from a signed card
(the first half of this page), and a **local MCP tool resource** an operator
has vetted, with no card (see [Enrolling a local MCP](#enrolling-a-local-mcp)).

## The life of an enrolled agent

One third-party agent, from a signed card an operator was handed to the
governed configuration it becomes and the contained run it is allowed. This
is `agenthof enroll`. It is the *install* side; for the *run* an enrolled
agent has, see [`lifecycle-spawn.md`](lifecycle-spawn.md) (an enrolled agent
runs only as a spawned child) and [`lifecycle.md`](lifecycle.md) (the run it
is). For the YAML, see [`trusted_signers`](reference/config.md#trusted_signers),
[`provenance`](reference/config.md) and the
[`enroll`](reference/config.md#control-plane-cli) command. For the executable
proofs, see the `enroll_*` journeys under
[`cmd/agenthof/testdata/script/`](../cmd/agenthof/testdata/script/) (fetch,
verify, consent, write, and the refusals, hermetically) and
[`scripts/e2e-refspawn-local.sh`](../scripts/e2e-refspawn-local.sh) (enroll →
apply → the enrolled agent spawns, and a root run of it is refused).

```
  operator                    agenthof enroll                         config dir      control ledger
    |  enroll <card-source>        |                                      |                 |
    |  --name N --role R           |-- authorized to enroll? --- no --------------------> refused (not_authorized)
    |                              |      | yes                            |                 |
    |                              |-- fetch the card (file | https) ------|                 |
    |                              |-- parse (strict) + VERIFY its JWS     |                 |
    |                              |     against trusted_signers --- no --------------------> refused (signature_failure)
    |                              |      | yes (one trusted kid)          |                 |
    |                              |-- content checks + Map;               |                 |
    |                              |     disclose what it REQUESTS +       |                 |
    |                              |     the card digest; write nothing    |                 |
    |  inspect (no --accept) ------|  <-- discloses, stops here (nothing recorded)           |
    |  --accept sha256:<digest> ---|-- re-fetch; digest still matches? -no------------------> refused (consent_declined)
    |                              |      | yes                            |                 |
    |                              |-- write NEW files only (agent,        |                 |
    |                              |     workflow, role) under the lock -->| agent/wf/role   |
    |                              |-- record the enrollment ----------------------------> success {signer, digest, requested, files}
    |                              |-- print the may_spawn + images: lines |                 |
    |                              |     for you to add by hand            |                 |
    |  apply  -> run as a spawn target (lifecycle-spawn.md); contained; refused as a root run
```

## What a card is

An agent card is JSON in the **A2A** shape (the interoperable agent-card
format), carrying an **Agenthof extension** that declares what the agent is
and what it needs: the artifact to run — an OCI image reference pinned by
digest (`ref@sha256:…`), a **host program** (a program id plus the content
hashes of its per-platform builds), or both — the interface it speaks (`a2a`), and the
capabilities it **requests** — tools, a model, an embedding model, and exec commands. The card is
**signed** (a detached JWS over its canonical bytes). You get it from a
**card source** you curate: a local file, or an `https` URL. A card is a
**request, never a grant** — nothing in it grants the agent anything; a human
consents, you `apply`, and the four doors enforce at run time regardless.

## What Agenthof checks, in order

Enrollment is a **control-plane action**, authorized the same way `apply` or
`enable` is: against the `enroll` operation a role declares, read from the
installed configuration. An unauthorized caller is refused **before anything
is fetched**, so `enroll` can never be turned into a fetcher. Then, on a
verified-authorized call:

1. **Fetch** the card — a local file or an `https` URL only. No shelling out
   to `git`, no cross-host redirects, a size cap and a timeout. ("A git repo
   of cards" means: clone it yourself, point `enroll` at the card file.)
2. **Parse**, strictly: duplicate, case-variant, and non-ASCII JSON keys
   rejected, size bounded, no trailing data. (Strict parsing is not cosmetic —
   a lax parser and the verifier disagreeing about which key wins is how a
   signed card gets read two ways.)
3. **Verify the signature first, before reading the card's contents.** The
   JWS must verify as **EdDSA** over the canonical card body against a key in
   the operator's [`trusted_signers`](reference/config.md#trusted_signers) —
   matched by key id, never a key taken from the card itself. With **no
   signers configured, every card is refused**: there is no trust by default
   and no way to skip the check. An unsigned card, an untrusted key, or a
   tampered body is a hard refusal. Only on a verified card does Agenthof read
   the extension and the requests.
4. **Fail fast on the content**: exactly one Agenthof extension, at least one
   pinned artifact form (an image digest or a host program's build hashes), and
   a supported interface, or a refusal that names the
   problem — still before anything is disclosed or written.

## Signing a card

If you curate cards, `agenthof card` makes and signs them locally. It reads
and writes only the files you name: it edits no configuration and contacts
nothing.

1. **Make a curator key pair.** `agenthof card keygen --dir curator` writes
   `curator/curator.key` (the private key, mode 0600; keep it with you) and
   `curator/curator.pub`, and prints the public key and a suggested `kid`. It
   never overwrites an existing pair. The printed `public_key` is the raw 32
   bytes in standard base64, exactly what a `trusted_signers` entry takes.
2. **Write the card.** A minimal one:

   ```json
   {
     "name": "Triage Bot",
     "version": "1.2.0",
     "capabilities": {"extensions": [{
       "uri": "https://agenthof.dev/ext/agent/v1",
       "params": {
         "artifact": "ghcr.io/acme/triage@sha256:<64 hex digits>",
         "interface": "a2a",
         "model": "fast",
         "tools": [{"resource": "code-search", "tools": ["search"], "mode": "read-only"}]
       }
     }]}
   }
   ```

3. **Sign it.** `agenthof card sign --key curator/curator.key --kid <kid>
   card.json` writes the signed card to stdout (or to `--out <path>`, which
   never overwrites). It refuses, writing nothing, a card that does not parse,
   one without exactly one Agenthof extension, an unreadable key, or an empty
   or over-long `kid`.
4. **Hand over the key and the card.** The operator who will enroll it adds the
   public key to the gateway's `trusted_signers`:

   ```yaml
   trusted_signers:
     - {kid: <kid>, key: <public_key>}
   ```

   and then runs `agenthof enroll signed.json ...` as described above.

Signing proves who vouched for the card, not that the agent is safe: the card
stays a request, and the operator's consent and the doors decide what it gets.

## The two-step consent

`enroll <source>` with no `--accept` **discloses and stops**: it prints
exactly what the card requests — the tools, model and embedding model it would be granted, the
exec commands (disclosed, never granted — see below), the artifact — with any
string that holds non-printable text refused rather than shown, and it prints
the card's **digest**. It writes nothing and records nothing.

`enroll <source> --accept sha256:<digest>` proceeds only if the re-fetched
card still hashes to the digest you consented to. The digest is the SHA-256
of the card's **canonical body with its signatures removed** — the bytes the
signature covers — so it is bound to what the signer signed, not to incidental
whitespace, and a re-signed card that changed nothing keeps the same digest.
A mismatch is a recorded decline.

## What gets written — and what does not

On accept, Agenthof writes **only new files**, created exclusively (an
existing agent, workflow, or role of the same name is never overwritten),
under the same writer lock `apply` takes, with the agent file written last.
If the enrollment cannot be recorded, the new files are removed — best-effort:
a crash between the write and the record can still leave files the ledger does
not know of, and those files, like any un-applied config, do nothing until a
recorded `apply`.

- an **agent** carrying a [`provenance`](reference/config.md) block (the
  artifact — whichever of the image reference and the host-program form the
  card carried — the card digest, the card version). The presence of that
  block makes the agent **spawn-only** (below).
- a **workflow** with one step naming it, and a **role** that owns that
  workflow. The role is dedicated to this agent and copies the
  `allowed_groups` of the `--role` you name as a snapshot — later edits to that
  source role do not follow — so you decide, at enroll time, who may invoke it.

The agent is written with the **requested** tool and model grants — but only
those that resolve to resources and models your own gateway already declares;
an unresolved id, a wildcard tool request, or an **exec** request is refused
or disclosed-but-not-granted rather than written, and a card that **requests a
sub-agent (`spawn`) is refused outright**. If the card names **no model**, the
agent is written with none and uses the gateway's default model at the model
door — a capability the card did not ask for, so `enroll` **discloses and
records that default** rather than letting it apply silently. **`may_spawn` is
never written from a card.** Granting a trusted agent the right to launch this
untrusted one is a deliberate edit you make by hand: `enroll` **prints** the
exact `may_spawn` line and the supervisor `images:` entry for you to add, and
names them; it does not add them for you.

Nothing takes effect until you `apply`. Config is law; the card cannot bypass it.

## How an enrolled agent runs

Because its `provenance` block makes it **spawn-only**, an enrolled agent
**cannot run as a root run**. `apply` rejects an `endpoint:` or an `exec` on
it — there is nothing to dial — and the engine refuses to start it as a root
run, whether from the command line or the serve API. It runs **only as a
spawned child** of a trusted orchestrator you grant `may_spawn`: the spawn
door provisions it a compartment through the supervisor, governs every
model/tool/exec/spawn call it makes, and records them. That run is [the life
of a spawn](lifecycle-spawn.md).

So you do not run an enrolled agent by trusting its code — you run it only
through the one path that puts a box around it, and you lean on the
supervisor's confinement **tier** (how strong that box is, below), not on the
card's honesty. A lying or unknown agent is as governed and as recorded as any
other; what the box is worth is the operator's deployment choice.

## The record

Only the decisions Agenthof *commits to* are recorded, each one event naming
the agent:

- **`success`** — the agent enrolled; the event carries the verifying signer's
  key id, the card digest, the capabilities requested, and the SHA-256 of each
  file written.
- **`refused` / `not_authorized`** — the caller held no `enroll` grant (this
  one is recorded *before* a fetch).
- **`refused` / `signature_failure`** — the card did not verify; nothing
  written, and no card payload on the event.
- **`refused` / `consent_declined`** — a wrong `--accept` digest; nothing
  written (the event carries the signer, digest, and requested set of the
  verified card).

A **verified** card that then fails a content check, a `Map` refusal (a
wildcard, a spawn request, an unknown tool or model), or config validation —
and a correct `--accept` that then hits a busy lock, a changed installed
config, or a write failure — is refused on **stderr and not recorded**: an
attacker should not be able to fill the ledger by throwing malformed verified
cards at it. (Control-plane faults that any command meets — a broken installed
snapshot, a torn control ledger — record or report as they do for `apply`;
see [`reference/config.md`](reference/config.md#control-plane-cli).) An
**inspect-only** run (no `--accept`) writes nothing and records nothing.

`agenthof audit control` renders the enrollment line (`agent <name> enrolled
(card …)`); `agenthof investigate` surfaces the record in the timeline. The
exit code is `0` on an inspect or a successful enrollment, `1` on a refusal or
error, `2` on a usage mistake.

## What is enforced today, and what is reserved

Only what ships is a guarantee.

- **Today:** containment (spawn-only, enforced by `apply` and the engine);
  the verified-signature trust gate; disclosure and byte-bound consent;
  request-is-not-a-grant; the audit record; and the **artifact binding**
  (below).
- **The artifact binding.** The artifact the card pinned and you consented to
  is the only one an enrolled agent is allowed to run as. Two independent
  checks enforce it at spawn time:
  - **The confiner refuses to launch** a compartment whose artifact is not
    the consented one. Under **podman** it inspects the local image, requires
    a consented digest to be among that image's digests, and then runs the
    exact image it inspected (by its immutable image ID, with no pull), so a
    retag between the check and the run cannot swap it. Under **Seatbelt** it
    hashes the resolved executable and refuses to run it unless the hash is a
    consented one.
  - **The gateway refuses to admit** a spawned child whose *measured*
    artifact (what the supervisor reports its compartment was launched with)
    is not in the consented set. It takes the consented artifact from its own configuration, not from
    anything the supervisor returns, and does not rely on the supervisor
    having enforced anything, so the binding
    holds even against a supervisor that is lenient or predates it. A refused
    child is never driven. This is the backstop: the usual refusal comes from
    the confiner (above), recorded with the reason `spawn artifact refused`
    and no set was handed to Agenthof, so no `max_total_spawns` slot is used. The
    gateway's own refusal is recorded as `spawn artifact not consented`, and
    because a compartment set was provisioned it does count against
    `max_total_spawns`.
  - The receipt records the measured artifact (runtime-reported): `audit` and `investigate` print the measured
    artifact on the spawn line (see [`lifecycle-spawn.md`](lifecycle-spawn.md)).
- **Both artifact forms are accepted.** `enroll` takes the OCI
  `ref@sha256:…` form and the host-program form (a program id plus
  per-platform content hashes) and records whichever the card carries; a card
  may carry only the host-program form. Podman binds the image digest;
  Seatbelt binds a program hash. An agent can run only on a backend that
  enforces a form it consented to: an enrolled agent that carries only the
  OCI form is refused on a Seatbelt supervisor, and one that carries only a
  host-program form is refused on podman.
- **Bound only when the gateway is upgraded.** The binding is enforced
  because the gateway sends the consented artifact and then checks the
  measurement. Against an older supervisor that reports no measurement, an
  enrolled agent is refused (fail closed). A gateway that does not send the
  consented artifact leaves the supervisor nothing to enforce, so the agent
  runs unbound. Upgrade the gateway to get the binding.
- **Reserved:** per-publisher (author) signing of cards, and anything not
  described above, is a later direction, not a guarantee.

The honest limits of the binding:

- **The measured value is runtime-reported evidence, not proof.** The
  gateway's check compares what the supervisor reports against what you
  consented to. A malicious or compromised supervisor that misreports the
  measurement defeats the gateway check; the gateway guards a lenient,
  older or misconfigured supervisor (for example a wrongly mapped image),
  not a lying one. The confiner's own refusal is the stronger of the two for
  the artifact it launches. Trusting the supervisor remains the operator's
  deployment choice.
- **Seatbelt binds the launched executable only.** The program hash covers
  that file's bytes. It does not cover libraries it loads, the interpreter a
  `#!` line names, or host files the program reads. The window between
  hashing the file and executing it is narrowed (the resolved file is the one
  executed, with no copy) but not closed: a writer to that file can still
  swap it in the gap. The program id binds nothing at run time (the path comes
  from the operator's mapping; only the hash binds), and arguments or scripts
  the executable loads are not covered. And a Seatbelt compartment is host-readable and has no
  resource caps (below). The podman image-digest binding is the stronger of
  the two.
- **A digest is not a verdict on the artifact.** The binding is about *which*
  artifact was launched, not whether that artifact is safe, and the measured
  value is runtime-reported, not proof. The doors still govern everything it
  does.

## Limits, stated plainly

- **The card is a request, never a grant.** On accept, Agenthof writes the
  requested grants, but every grant resolves against your own gateway, no
  wildcard and no `may_spawn` is taken from a card, and the doors enforce
  default-deny at run time regardless of anything the card claimed.
- **The ledger records *verified* provenance; it does not make unverified
  agents impossible.** Anyone who can write the configuration directory can
  hand-author the same agent file, with the same `provenance` block, and no
  `enroll` event. What `enroll` guarantees is that *its* path verifies a
  signature and records what it verified — not that nothing else can put an
  agent in config. The config directory is still the operator's to protect.
- **Trust is the curator's signature.** In this release a card is signed by
  the curator of the repo you pull it from, already mapped to your namespace;
  you trust that key. Per-publisher (author) signing is a later direction.
- **Containment is the supervisor's, graded on the record.** As with any
  spawn, Agenthof runs nothing and confines nothing itself; how strong the box
  is depends on the tier the run's spawn line names — a shared-kernel container
  or OS sandbox, never a VM — and is the operator's deployment choice. Under
  the Seatbelt tier in particular a child is **host-readable** (it can read any
  file the operator's user can, outside the supervisor's own roots) and runs
  with no resource caps; the podman tier is a shared-kernel container. See
  [`lifecycle-spawn.md`](lifecycle-spawn.md#limits-stated-plainly). What
  Agenthof guarantees is that the agent runs *only* where the supervisor put
  it, governed and recorded, or not at all.

## Enrolling a local MCP

An operator has installed a local MCP server (a program that speaks the Model
Context Protocol over stdio) and wants it governed: reachable only through
the tool door, only by an agent that is granted it, and only for the tools
the operator named. There is no signed card here. The operator **is** the
vetting: they chose the install, the command and the tools, and
`enroll mcp` records that decision. The ceremony has the same shape as the
card journey: authorize, disclose, consent by digest, write, record.

```
  operator                 agenthof enroll mcp                   working config    control ledger
    |  enroll mcp <name>        |                                      |                 |
    |  --command ... --socket   |-- authorized to enroll? --- no --------------------> refused (not_authorized)
    |  --token-env --tools      |      | yes                           |                 |
    |                           |-- name free? validate the proposal    |                 |
    |                           |     in memory (nothing written)       |                 |
    |  inspect (no --accept) ---|  <-- discloses argv, env NAMES, egress, tools,         |
    |                           |      accept-digest; stops (nothing recorded)           |
    |  --accept sha256:<d> -----|-- digest of the proposal matches? -no----------------> refused (consent_declined)
    |                           |      | yes                           |                 |
    |                           |-- edit in place, under the lock ----->| tool resource   |
    |                           |     (+ with --grant: one read-only    | (+ one grant)   |
    |                           |      grant on the named agent)        |                 |
    |                           |-- re-validate the written files       |                 |
    |                           |-- record the enrollment -----------------------------> success {resource, command,
    |                           |                                       |                  env names, tools, egress,
    |                           |                                       |                  granted_to, digest, file hashes}
    |  apply  -> installs; refbridge launches the MCP from the governed slice;
    |            the tool door verifies the command and enforces the grant
```

### What the operator supplies

```
agenthof enroll mcp <name> --command "<abs argv>" --socket <abs path> \
    --token-env <NAME> --tools a,b [--env N,..] [--egress host,..] \
    [--grant <agent>] [--from-paste] [--accept sha256:<digest>]
```

- **The command** is the launch argv; its first element must be an absolute
  path to an install you already made. A fetch-at-spawn launcher (`npx`,
  `npm`, `uvx`, `pipx`, `bunx`) is refused: it would pull whatever the
  registry serves at launch time, so there is nothing pinned to vet.
  `--from-paste` reads a pasted `{command, args, env}` MCP configuration on
  stdin instead; every pasted env **value** is discarded on the spot, and only
  the names survive.
- **The socket and token variable.** `--socket` is the absolute path the
  bridge fronts the MCP on; `--token-env` is the **name** of the environment
  variable the gateway reads the bearer token from. A value in that slot is
  refused, never echoed.
- **The tools.** `--tools` names the read-only tools explicitly. `*` is never
  written. **Nothing is run at enroll time** to discover them: the operator
  states them, and the door later holds the agent to exactly that list.
- **Env names and egress.** `--env` lists environment variable **names** to
  pass through to the MCP, never values. `--egress` lists the hosts it may
  reach; empty means no network.

### Authorization, disclosure, consent

Like the card journey, enrollment is authorized against the `enroll` control
operation a role declares in the installed configuration; an unauthorized
caller is refused first and the refusal is recorded.

With no `--accept`, `enroll mcp` **discloses and stops**: the exact argv, the
environment variable names, the declared egress, the read-only tools, whom (if
anyone) they would be granted to, the resource exactly as it would be written,
and an **accept-digest**, the SHA-256 of that proposed resource. It writes
nothing and records nothing. The digest binds the resource body shown; check
the name and the `--grant` target yourself, they are not inside it.

`--accept sha256:<digest>` proceeds only if the proposal still hashes to the
digest you consented to. A mismatch is a recorded `consent_declined`.

### What gets written

On accept, under the same writer lock `apply` takes, Agenthof edits the
**working** configuration in place (comments and layout are preserved):

- a **tool resource** in `gateway.yaml` carrying the governed launch spec:
  the command, the env names, the egress and the read-only tools; and
- if `--grant <agent>` was given, one **named read-only grant** of exactly
  those tools on that agent's file.

It then reloads and re-validates the written files, and only then appends the
`enroll_mcp` event. Any failure before that reverts the edits.

**Propose, not install.** `enroll` writes the working configuration and
ledgers the decision; it installs nothing. `apply` is its own act. And with no
`--grant`, the resource is written **inert**: unreachable by any agent until
one is granted it (default-deny).

### The record

One event, `enroll_mcp`, authorized by the `enroll` operation, carrying: the
resource name, the command, the env names, the read-only tools, the declared
egress, the agent it was granted to, the accept-digest consented to, and the
SHA-256 of each file written. There is **no card digest and no signer**,
because there was no card. A wrong `--accept` records `refused` /
`consent_declined`, and a caller without the grant records `refused` /
`not_authorized`. Other refusals (a name already in use, a configuration that
does not load or validate, a busy lock, a changed installed configuration)
print on stderr and are not recorded. `agenthof audit control` renders the
line `resource <name> enrolled`; the command and the rest stay in the record
for anyone reading it raw.

### How an enrolled MCP runs

After `apply`, the resource is part of the installed configuration. refbridge
launches the MCP from that governed slice, inside the supervisor's
compartment (see [`lifecycle-spawn.md`](lifecycle-spawn.md)). Each tool call
then passes the tool door, which verifies the launched **command** against the
applied configuration and enforces the grant's allowlist: an agent can call
only the tools it was granted, and an ungranted agent cannot reach the
resource at all. The call is ledgered like any other tool call
([`lifecycle.md`](lifecycle.md)).

### What is enforced today, and what is reserved

Only what ships is a guarantee.

- **Today:** the `enroll` authorization; disclosure and digest-bound consent;
  the in-place, validated, reverted-on-failure edit; the inert default;
  the explicit read-only allowlist; the command check at the door; the
  audit record.
- **Reserved, not shipped:** remote MCP enrollment by URL; a secret store
  beyond environment variables (such as a keychain); `connect`/OAuth
  flows; a chat front for enrollment; cryptographic attestation of the
  launched program; and listing an MCP's tools by asking it.

### Limits, stated plainly

- **The pin is the operator's vetted install path, not a measurement.**
  Agenthof does not hash or fingerprint the MCP's code. It checks that the
  command it launches is the command you consented to. Whether that program
  is trustworthy is your judgment, made when you installed it.
- **The door verifies the command only.** `env_passthrough` and `egress` are
  declared configuration, recorded and disclosed, but not checked by the door
  at call time. What a compartment can actually reach is the supervisor's
  tier, as for any spawn.
- **The command is permanent.** The argv is written verbatim to the
  configuration and to the append-only ledger, and cannot be taken back out.
  Put secrets in environment variables (names only), never in arguments.
- **Two crash windows, inherent to writing first and recording second.**
  If the process dies after the configuration is edited but before the event
  is appended, the files are changed with no record, and re-running then
  refuses with "already a tool resource". And if an append reaches disk but
  returns an error, the edits are reverted while a recorded success remains
  whose file hashes describe files that no longer exist as written. Either
  way the edit does nothing until a recorded `apply`, and the ledger is the
  limited, not-tamper-proof evidence described in
  [`concepts.md`](concepts.md), not a guarantee that no one else wrote the
  configuration.

## See also

- [`lifecycle-spawn.md`](lifecycle-spawn.md) — the contained run an enrolled agent has.
- [`lifecycle.md`](lifecycle.md) — the life of a run.
- [`reference/config.md`](reference/config.md#control-plane-cli) — the `enroll` command, `trusted_signers`, `provenance`.
- [`concepts.md`](concepts.md) — the what and why behind the doors and the ledger.
