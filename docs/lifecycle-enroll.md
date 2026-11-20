# The life of an enrolled agent

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
and what it needs: the artifact to run (an OCI image reference pinned by
digest, `ref@sha256:…`), the interface it speaks (`a2a`), and the
capabilities it **requests** — tools, a model, and exec commands. The card is
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
4. **Fail fast on the content**: exactly one Agenthof extension, a pinned
   artifact digest, and a supported interface, or a refusal that names the
   problem — still before anything is disclosed or written.

## The two-step consent

`enroll <source>` with no `--accept` **discloses and stops**: it prints
exactly what the card requests — the tools and model it would be granted, the
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
  artifact reference, the card digest, the card version). The presence of that
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
  request-is-not-a-grant; the audit record.
- **Recorded but not yet enforced at launch:** the artifact **digest**. The
  card pins `ref@sha256:…` and `enroll` records the digest you consented to,
  but today Agenthof does **not** yet bind the *running* compartment to that
  exact artifact — the operator fetches the image and maps it in the
  supervisor's config, and a later release will make the confiner refuse
  anything but the consented digest (an image digest under podman, a program
  content hash under Seatbelt). Until then, treat the recorded digest as
  provenance you consented to, not proof of what ran.
- **OCI only, for now:** `enroll` accepts the `ref@sha256:…` artifact form;
  the Seatbelt program-plus-hash form arrives with the launch-time binding.

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

## See also

- [`lifecycle-spawn.md`](lifecycle-spawn.md) — the contained run an enrolled agent has.
- [`lifecycle.md`](lifecycle.md) — the life of a run.
- [`reference/config.md`](reference/config.md#control-plane-cli) — the `enroll` command, `trusted_signers`, `provenance`.
- [`concepts.md`](concepts.md) — the what and why behind the doors and the ledger.
