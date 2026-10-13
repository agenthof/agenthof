# The life of a control action

[`lifecycle.md`](lifecycle.md) follows a single `agenthof run` — the *data
plane*, where work happens. This page follows a single **control action** — the
*control plane*, where the rules that govern that work are changed: applying a
configuration, flipping an agent's kill switch, or repairing the ledger. It
traces one command from the moment you type it to the audit trail you read back.

If [`concepts.md`](concepts.md) is the *nouns* and [`constitution.md`](constitution.md)
is the *law*, this page is the *verbs* of governance: who changed what, and
whether that record can be trusted afterward.

Everything below describes what ships **today**. Where something is reserved for
a later version, it says so — only shipped behavior is a guarantee.

## The commands

Six commands write to the control plane — one of them, `apply`, can
also arrive over the network, and one, `config vouch`, is a recovery act rather
than a change:

```
agenthof apply --config ./config --as dana@example.com --groups platform-eng                   # adopt a configuration
agenthof registry disable coder --config ./config --as dana@example.com --groups platform-eng  # the kill switch: re-installs the configuration with coder disabled
agenthof registry enable  coder --config ./config --as dana@example.com --groups platform-eng  # …and back on
agenthof audit repair control --config ./config --as dana@example.com --groups platform-eng    # repair a torn ledger tail
agenthof gateway provision --as dana@example.com --groups platform-eng                           # mint provider keys for the installed roles
agenthof runs prune --older-than 180d --as dana@example.com --groups platform-eng               # remove aged run ledgers and artifact bodies
agenthof config vouch --control-log .agenthof/control.jsonl --as dana@example.com              # record the install event the ledger lacks for the snapshot already installed (recovery)
agenthof apply --server https://agenthof.example --token $TOKEN --if-installed sha256:…  # the same apply, over the API (serve)
agenthof config pull --server https://agenthof.example --token $TOKEN --out ./pulled           # read the installed configuration back, for an execution point (a read: not recorded)
```

Each one is an *attempt* to change governance state, and each attempt — whether
it succeeds, is rejected, or is refused — is recorded to a single, append-only,
hash-chained **control ledger** (`.agenthof/control.jsonl`). The control plane's
promise is not that nothing bad can happen; it is that **nothing happens without
a record you can later verify**. One command reads the control plane without
writing it: `config pull` hands an execution point the installed
configuration, authorized like every control action and — because it changes
nothing — not recorded. And one writes a record without changing any
configuration: `config vouch` makes the ledger stand behind a snapshot that is
already installed but whose install event never landed — see "Recovering an
unrecorded install" below.

## The journey at a glance

```
  agenthof apply / registry enable|disable / audit repair control / gateway provision / runs prune
      │
      ▼
  1. Who is changing it?   authenticate  ──►  Invoker {subject, issuer, method}
      │                                        + asserted_as (claimed) + witness (machine)
      ▼
  2. May they change it?    the installed snapshot's bytes must hash as its pointer, the control
      │                     ledger must record that pointer as its last install (not → refused /
      │                     not_on_record, recorded*), then authorize ──► no ──► refused / not_authorized (recorded*, then stop)
      │ yes                                           *repair: printed, not recorded; it verifies the bytes but does
      │                                                not consult the ledger it repairs (see below)
      ▼
  3. Is the change valid?  validate  ──►  no ──►  rejected / refused  (recorded, then stop)
      │ yes   (apply: the validated copy is installed as the current snapshot)
      ▼
  4. Record it            open the Locked ledger, append a control/1 event:
      │                     { action, outcome, invoker, witness, config_hash, seq, prev }
      │                     outcome ∈ success | rejected | refused | error — ALL recorded
      ▼
  5. Return the head       print the new chain head (a hash) — save it off-machine
      │
      ▼
  6. Read it back          agenthof audit control        ──► the story, in order
                           agenthof audit verify control ──► verified | torn | broken | tainted
```

## 1. Who is changing it? (three identities)

Every control record carries **three** independent answers to "who," so a later
reader never has to take one of them on faith (Article II):

- **invoker** — the identity the action is *attributed to*: `{subject, issuer,
  method}`. With `--as` it is self-asserted (`method: asserted`, `issuer:
  local`); with `--token` it is an OIDC identity the platform **verified**
  (`method: oidc`), and `AGENTHOF_OIDC_ISSUER` must be set or the command exits
  with a usage error before doing anything.
- **asserted_as** — the raw identity the caller *claimed*, recorded alongside the
  verified invoker when the two can differ, so a mismatch is visible rather than
  silently overwritten.
- **witness** — the local `os_user` and `hostname` of the machine that actually
  ran the command, captured independently of the asserted invoker. The invoker
  says who *asked*; the witness says where it *ran*.

A `--token` that fails verification is not a silent no-op: it is recorded as a
`refused` event (reason `token_verification_failed`) and the command exits
non-zero.

## 2. May they change it? (authorization)

Knowing who asked is not the same as letting them. Every control action is
**authorized, default-deny**, from two facts: the invoker's groups and the
roles in the configuration directory. A role may carry a `control:` grant —
any of `apply`, `enable`, `disable`, `repair`, `provision`, `prune`, `pull`, named one by one, no wildcard —
and the action is allowed only if some role both names one of the invoker's
groups in `allowed_groups` **and** lists that operation. Membership and grant,
never the grant alone. One grant includes another: a grant of `apply`
includes `pull` (whoever may change the configuration may read it); nothing
else is implied. A role with no `control:` grants nothing; a public role
(`allowed_groups: ["*"]`) can never grant a control operation, and `apply`
rejects one that tries. A role may grant control operations and own no
workflows at all — an operator who changes governance but runs nothing.

```yaml
# config/roles/platform-admin.yaml
name: platform-admin
allowed_groups: [platform-eng]
control: [apply, enable, disable, repair, provision, prune]
```

Two of the operations guard commands that change no configuration but are
control-plane actions all the same. `gateway provision` mints a provider key
at the model gateway for every **installed** role that owns workflows — what
the last `apply` installed, never a directory — and records `provision`
with the installed configuration's hash; that record is not an install
(`audit verify control` and a run's config-join ignore it). `runs prune`
removes aged run ledgers and artifact bodies and records `prune` with a
one-line `detail` of what it removed and no hash: it installs nothing and
reads no configuration. Both refuse, recorded, when nothing is installed —
there are no roles to authorize against, and prune has no directory to fall
back to (the kill switch and repair do, while nothing is installed, because
each has a directory in hand) — so after removing `installed/current` a
retention job is refused until the re-bootstrap apply lands. A provision
that fails on one role stops there: keys minted for earlier roles persist,
one `error` record names the role that failed, and a re-run finds the
earlier keys valid. A provision or prune whose success event could not be
appended prints `provision ran; event NOT recorded` / `runs pruned; event
NOT recorded`; nothing downstream flags a provision's gap (there is no
pointer to compare), so the operator re-runs it.

`pull` guards the one control-plane action that is a read: `config pull`
(and `GET /v1/config`) hands the installed configuration to an execution
point so it can enforce it. It is authorized against the installed roles like
every other action and, as a read, records nothing — see "Pulling the
configuration" below.

One command is deliberately outside this gate: `config vouch` is authorized
against no role (`vouch` is not an operation a role can grant). It is a
bootstrap-class recovery act, permitted for any identity the host resolves and
always recorded — see "Recovering an unrecorded install" below.

What each command authorizes against — the **installed** configuration:

`apply` does more than validate. A configuration that passes is **installed**:
copied, file by file, into a content-addressed snapshot under
`.agenthof/installed/<hash>/` (beside the control ledger), and a one-line
pointer, `.agenthof/installed/current`, is switched to it. That snapshot — not
the directory on disk — is what every later control action authorizes against:

- **`apply`** — the roles of the configuration **already installed**. The
  configuration being applied cannot authorize itself: a caller cannot grant
  their own group `control: [apply]` in the very change they are applying,
  because the decision is made before the change is even read. Once the
  change passes and is installed, *its* roles govern the next apply.
- **`registry enable|disable`** — the installed roles as well. With something
  installed the flip does not edit `--config`: it stages a copy of the
  installed snapshot, flips the one bit on the copy, and installs the copy — a
  new snapshot, a new `config_hash` on its record. `--config` is read only
  while nothing is installed yet (the bootstrap-era fallback), where it is the
  only configuration there is: the bit is flipped there, the record is marked
  `bootstrap`, and the first `apply` installs the directory as flipped.
  **`audit repair control`** — the installed roles; `--config` only while
  nothing is installed.
- **Bootstrap.** A fresh control root has nothing installed, so there is nothing
  to authorize against: the **first apply is permitted**, whoever asks, and is
  recorded with a `bootstrap` marker (`audit control` shows it as `config
  applied (bootstrap)`; a kill-switch flip run in this same pre-install window
  shows instead as `enabled agent coder (nothing installed; directory edited)`
  — it edited the configuration directory and installed nothing, so an apply
  marked bootstrap installed the first snapshot but a flip so marked did not).
  Until that first apply, the kill switch and repair fall
  back to the roles in `--config`, so a fresh system is never locked out. An
  existing control root that already has recorded applies but no installed
  snapshot — the first apply after this behavior arrives — is treated the same
  way: that apply bootstraps, whoever asks, and installs the snapshot the root
  then authorizes against.
- **The floor.** A configuration that grants `apply` to no role — or only to
  roles whose `allowed_groups` name no real group — is rejected
  (`no-apply-floor`): installed, it could never be changed again.

The authorizing roles are read from the snapshot in three steps, and it is
worth keeping them apart. First the snapshot's **bytes are verified** against
the pointer's hash — every enumerated file, not only `roles/` — before any of
them is parsed; a mismatch (`installed config <hash>: snapshot hashes as
<got>, not as its pointer`) authorizes nobody, so an edited snapshot decides
nothing. Second, the **pointer must be the install the control ledger records
last** — the last successful `apply`, kill-switch flip, or `config vouch` on
record — or the action is refused, recorded, `configuration not on record`;
this is the same vouch the execution read performs, and `apply`, the kill
switch, `gateway provision` and `runs prune` all require it. `audit repair
control` is the one exception: it verifies the bytes but does not consult the
ledger, because the ledger it would consult is the one it exists to repair.
Third, the roles are **parsed leniently** — roles only, never the full
validation `apply` runs — so an installed configuration written under older
rules, or a kill-switch snapshot that references a disabled agent, still
decides who may change it. The control plane reads the snapshot's roles to
authorize; `run` and `serve` read the whole snapshot to execute — the data
plane runs the installed configuration too, not the `--config` directory.

A refused `apply`, `enable`, or `disable` is recorded like every other
turned-away attempt — outcome `refused`, reason `not_authorized`, a fixed
message that names the operation and nothing else (never the caller's claimed
groups), and for `apply` the hash of the configuration they tried to apply.
A pointer the ledger does not vouch for is refused before authorization is
even attempted — reason `not_on_record`, the text naming the last recorded
install (or that there is none) and the remedy — so a caller no role grants
learns that the pointer is unvouched, never the pointer's own hash. A
refused **repair is printed, not recorded**: the only ledger it could be
written to is the damaged one being repaired. The same holds when the roles
cannot be read or verified at all — repair refuses, prints why, and touches
nothing.

**Honest limits.** In CLI mode the filesystem is the root of trust. Anyone who
can edit the configuration directory can edit `control:` too, so this gate is
a *recorded default-deny decision* on the invoker's identity — meaningful
under `--token`, where the groups are verified; self-asserted under `--as
--groups` — not a wall against someone who already holds write access to the
files. Every read of the installed snapshot's bytes verifies them against the
pointer before parsing them: the execution read (`run`, `serve`), the
authorization read every control command decides with, the kill switch before
it stages a copy to re-install, and the pull before it serves a byte. All stop
on a mismatch (`installed config <hash>: snapshot hashes as <got>, not as its
pointer`), so tampered bytes are neither executed, nor authorized from, nor
re-installed under a new name, nor distributed. The pointer itself is held to
the ledger: `run` and `serve` execute, and `apply`, the kill switch, `gateway
provision` and `runs prune` authorize against, only a snapshot the control
ledger records as its **last install**, and refuse — recorded, `configuration
not on record` — a pointer re-aimed by hand, a dropped-in snapshot, or an
install whose record never landed; a damaged ledger refuses runs and control
actions, with the repair hint, until it is repaired (`audit repair control` is
the one command that does not consult the ledger — it repairs it). The
ledger's account of what is installed therefore changes only by a recorded
`apply`, kill-switch flip, or `config vouch`. So the store is tamper-evident,
not tamper-proof: whoever can write the store *alone* can no longer make a
run execute, or a control command authorize from, a re-pointed, dropped-in,
or edited snapshot — and whoever can rewrite the store and the ledger
together, consistently, can still install or re-point at will: the ledger's
own writer. That consistent rewrite is what a head saved off the machine
catches today (`audit verify control --expect-head`) and what external
anchoring (reserved) would prove to a third party. Two narrower limits are
worth naming. `audit control` and `audit verify control` compare the pointer
with the ledger and never hash the snapshot's bytes, so a store whose bytes
were edited in place reads "matches the last recorded install" there while
every control command and every run refuses it. And `gateway provision` and
`runs prune` hold the configuration lock only *shared*, across their one read
of pointer, roles and ledger, and release it before they mint or remove
anything, so an `apply` that lands concurrently and revokes the invoker's
grant may be a few milliseconds too late — the same window a run's per-run
read has; provision reads the roles once and mints for exactly the roles it
authorized against, so there is no second window. Two remedies, for two
different faults. A pointer the ledger does **not vouch for**, whose bytes
verify, is healed by `agenthof config vouch --control-log <path>` — the
recovery described below, which leaves the bytes exactly as they are. Bytes
that do **not hash as the pointer** (or a pointer that is malformed, or names
a snapshot that is gone) are never vouched; the remedy is to remove
`installed/current` and `apply` again — a fresh, correct snapshot if the bytes
differ; if a corrupt directory already exists under that name, `apply` refuses
with a removal hint, so remove `installed/<hex>` too and `apply`. Re-applying
the directory re-asserts its declared state, so it re-enables any agent a
kill-switch flip had disabled. The kill switch is a break-glass override of
the **installed** configuration and is temporary by design (see below). A
`run` executes a snapshot that either the old or the new install put in
place, whole — the pointer is renamed atomically — so an `apply` racing a
served run is safe; a flip racing an `apply` is two writers under one lock,
one after the other, both recorded. What the gate buys now is that an
unauthorized change attempt yields a `refused` row instead of a silent change
— and that a change cannot smuggle in its own permission. The proposed
configuration is read once: it is copied into the store first, and the copy is
what is validated, hashed, and installed, so the recorded hash is the hash of
exactly what was checked. And the store is a logic gate, not a vault: it has
two doors that no role guards, both open to whoever has the host's filesystem
and its CLI. Whoever can write `.agenthof/installed/` can remove `current`,
and the next apply is a bootstrap again for any identity — the only trace is a
second `config applied (bootstrap)` row in the audit trail, which is exactly
why it is recorded distinctly. And whoever can run `config vouch` can make the
ledger stand behind whatever snapshot `current` names, provided its bytes
verify and its roles still let someone apply — the only trace is a distinct
`vouch` row, under the invoker's three identities, naming what the ledger
vouched for before. Both doors are recovery acts, not authorization gates:
their safety is attribution and visibility, not prevention, and the second is
no weaker than the first — anyone who can place a snapshot to vouch for could
already obtain the same authority through the bootstrap door, by installing a
configuration with the same roles. That first door is also the
deliberate way out when an installed configuration locks out its own control
(it grants `apply` or `repair` only to a group no verified token carries):
re-bootstrap, and the record shows it. The gate is per control root, not per
store: the installed snapshot is found beside the `--control-log` in use, so
pointing a command at a fresh `--control-log` reaches the bootstrap /
`--config` fallback with no write to any store at all. That grants nothing an
operator did not already have, but it is why the control root, not the store
directory alone, is the boundary to reason about. Over the API that limit
falls away for the caller: there is no filesystem, so the token-and-roles
check is the only way in, the first apply while nothing is installed is
refused unless the server was started with `--allow-api-bootstrap`, and
`config vouch` is not offered at all. What remains is the host: whoever can
write `.agenthof/installed/` on the serving host can still remove the pointer,
and whoever can run the CLI there can vouch. A pull reads the installed
snapshot whole and verifies every byte against the pointer before serving any
of it, so it never distributes a tampered snapshot; who may pull is decided
from the same byte-verified roles, and nothing is served unless the ledger
vouches for that same hash — but the pull checks the ledger after it
authorizes, not before, and no ledger line records that a pull happened.

## 3. Is the change valid?

What "valid" means depends on the action:

- **`apply`** builds and validates the whole configuration (roles, workflows,
  agents, gateway) before adopting it. A configuration that fails validation is
  recorded as **`rejected`** (reason `validation_failed`) — together with the
  hash of the config that was rejected, so you can see exactly *what* was turned
  away. It also checks that at least one role grants `apply` to a named group
  (`no-apply-floor`). A configuration that passes is installed — see §2.
- **`registry enable|disable`** checks that the named agent exists — looked up
  in the installed snapshot once something is installed, so an agent added to
  the directory but not yet applied is `agent_not_found`; an unknown
  agent is recorded as `refused` (reason `agent_not_found`) — `rejected` means a
  change was evaluated and turned down, while `refused` means the actor or target
  wasn't admitted in the first place (the invoker was authorized first — see §2;
  an unauthorized caller is refused before the agent lookup, so the agent list
  is not probeable).

Either way the outcome is written down. A turned-away change is a governed event,
not an error swallowed at the door.

## The kill switch under an installed configuration

> The kill switch is a break-glass override of the **installed** configuration.
> It does not edit your configuration directory. The declared state — the
> directory, usually under version control — is what `apply` installs; an
> `apply` after a `disable` re-asserts the declared state, agent enabled, and
> is recorded as the apply it is. To make a disable permanent, set `enabled:
> false` in the agent's file and apply it; to see the override's history,
> `audit control` shows the flip and the apply that superseded it, each
> attributed.
>
> A flip first verifies the installed snapshot's bytes against the pointer and
> requires the ledger to vouch for that pointer; a byte mismatch stops the flip
> and is recorded as an `error`, an unvouched pointer as a `refused`
> (`not_on_record`), both before anything is staged, so a tampered or unrecorded
> snapshot is never re-installed under a correct name. If the flip itself lands
> but its record does not (`state changed; event NOT recorded`), `config vouch`
> puts the flipped snapshot on record with the agent still disabled — see
> "Recovering an unrecorded install".

The sequence is short. A `disable coder` re-installs the configuration with
`coder` disabled; a `run` of any workflow is then refused `configuration
invalid: … workflow "fix-bug" depends on agent "coder", which is disabled in
the registry`, recorded as a refused run; `audit control` shows who flipped it;
and `apply` re-asserts the directory (or `enable` flips the bit back).

The realistic hazard is not an operator who forgets but a **scheduled or
pipeline `apply`** — a configuration directory under version control, applied
by CI or a cron on every merge or tick — which reverts an emergency `disable`
on its next run with nothing more than a `config applied` line in the control
ledger, minutes after the responder flipped the switch. Two correct responses:
make the disable declared (`enabled: false` committed and applied), or pause
the pipeline.

Disabling an agent takes every workflow that references it — and, today, every
other workflow in the configuration — out of service until it is re-enabled or
applied around: a kill switch that stops everything is fail-closed; the cost is
availability, not containment.

## 4. Record it on the chain

A valid change (and every rejection and refusal above) is appended to the
control ledger, which is:

- **Locked** — the writer takes an OS file lock (`flock`) for the append, so two
  concurrent control commands cannot interleave and corrupt the chain.
- **Hash-chained** — every record stores a `seq` (contiguous, starting at 1) and
  links to the hash of the record before it (`prev`). The chain is over the raw
  bytes on disk, so any later edit to an earlier line breaks the link at that
  point and every point after it.
- **Contiguous** — the unbroken `seq` from 1 is what distinguishes a control log
  from a run log (which carries no `seq`); a gap is itself evidence.

The record is a **control/1** event: `{ action, outcome, invoker, asserted_as,
witness, config_hash, seq, prev, … }`. The `outcome` is one of `success`,
`rejected`, `refused`, or `error`, and **all four are recorded** — the ledger is
a log of *attempts*, not only of successes.

**Honest limits.** There are three narrow cases the ledger names rather than
hides. If the ledger is already **torn or broken** when a command runs, the
command records nothing new, exits non-zero, and tells you to run `audit repair
control` first — a damaged chain is not appended to. And a `registry`
flip that lands but whose recording append then fails prints `state changed;
event NOT recorded` — the one case where state changed with no event to show for
it. An `apply` has the same shape: once its snapshot is installed and the
pointer switched, a recording append that then fails prints `installed; event
NOT recorded` and exits non-zero. `audit control` and `audit verify control`
compare the installed pointer with the last recorded **install** — the last
successful `apply`, kill-switch flip, or `config vouch` on record — and say
when the two disagree (`verify control` exits 5), so an unrecorded install is
visible rather than silent — and `run` and `serve` refuse every run under it,
and every control action is refused too, recorded as `configuration not on
record`, until `config vouch` puts the install on record (a re-apply is
refused the same way, because it too must authorize against a vouched
pointer). Both are surfaced loudly; neither is glossed over.

**Upgrading.** A control root written before this behavior whose last successful
control event is a kill-switch flip over a configuration directory reports
`audit verify control` exit 5, and refuses every run and every control action
(`configuration not on record`, recorded) — the flip recorded a directory hash
that was never installed — and its earlier bootstrap-era flips carry no marker.
Run `config vouch` once after upgrading (or remove `installed/current` and
`apply`); `apply` alone is refused until the pointer is vouched for.

**The integrity posture.** Where the ledger's bytes live, and whether its head
is pinned to an off-machine anchor, is declared in an `integrity.yaml` beside
the ledger (absent means the default). The only posture this build honours is
the local hash-chained file this section describes — sink `local`, anchor
`none`. A posture naming any reserved sink or anchor is one the build cannot
honour, so every control write — `apply`, a `registry` flip, `config vouch`,
`gateway provision`, `runs prune`, `audit repair control` — refuses before it
opens the ledger, rather than appending under a guarantee it does not provide;
`serve` reads the posture once at startup and refuses to start on one it cannot
honour, so a running server keeps the posture it read and a change to the file
takes effect on restart. The schema reserves one further shape it never writes
yet: an `anchor` record — a control-ledger record kind the readers already
understand, reserved for a future external-anchoring tier to pin the head,
written by nothing today.

### Recovering an unrecorded install

The gap above — a snapshot in place whose install event never landed — has one
in-band remedy that leaves the configuration untouched:

```
agenthof config vouch --control-log <path> [--as <user> --groups <a,b> | --token <jwt>]
```

Pass the same `--control-log` the install used: the store is found beside it,
and vouching against the wrong control root records nothing useful. The
command reads the pointer, **verifies the snapshot's bytes** against it,
checks that its roles still grant `apply` to a named group (the same floor
`apply` enforces, so a vouched snapshot is never one that nobody may apply),
and — if and only if the ledger does not already record that hash as its last
install — appends one `vouch` event for it, then signs the install when a
signing key is configured. It prints `vouched: <hash>` and the new chain head.
That is all it does. It moves no pointer, copies no bytes, builds nothing, and
never touches the configuration directory: an agent a kill-switch flip disabled
stays disabled, which is why a flip's crash gap is healed this way and not by
re-applying the directory (which would re-enable it, and is refused on an
unvouched pointer anyway).

What it refuses, and what it does not do:

- **Bytes that do not hash as the pointer**, a malformed pointer, or a snapshot
  that is gone are never vouched for: the command prints the fault and the
  hatch (remove `installed/current` and re-bootstrap), and records an `error`.
- **A torn or broken ledger** is not appended to: run `audit repair control`
  first.
- **Already on record** does nothing: it prints that the hash is on record,
  exits 0, appends nothing and writes no signature — so it is safe to run twice
  or from a script.
- **Nothing installed** is not a vouch: there is nothing to stand behind.
- A roles file whose `apply` grant names no real group is `rejected`
  (`no-apply-floor`), recorded.

It is authorized against no role — `vouch` is not an operation a role can
grant — because the question it answers is whether the roles themselves are on
record. Like the first `apply`, it is permitted for any identity the host
resolves, and like every control action it is **always recorded** under the
three identities, with a `detail` naming what the ledger vouched for before
(`previously on record: <hash>, apply`, or `no install on record`). Its safety
is that attribution and visibility, not prevention: whoever can run it can
bless whatever `current` names — and could already have obtained the same
authority through the `rm current` + bootstrap `apply` door, so it widens
nothing. A
`--token` that fails verification is refused and recorded, as everywhere.

When to prefer the other door: `rm installed/current` followed by `apply
--config <dir>` is right when you want the *directory's* declared state back,
knowing it re-enables anything a flip disabled; `config vouch` is right when
you want exactly what is installed to stand.

Three consequences to know before running it:

- **Upgrade every binary that shares the control root first.** An older
  `agenthof` does not recognise a `vouch` event as an install: its `run` and
  `serve` keep refusing the healed pointer as `configuration not on record`,
  its `audit control` reports a mismatch, and its `config sign` reports "not
  yet on record". The record is additive and harmless; the older binaries
  simply fail closed until upgraded.
- **After a repair, a pinned execution point may read *stale*.** If `audit
  repair control` truncated a torn tail that a pinned point had already
  verified past, the vouch (like any install after that repair) lands at a
  sequence number below that point's `verify.floor`; it is refused *stale*
  there until the operator removes `verify.floor` on that point. That is the
  repair's consequence, not the vouch's.
- **The ledger's account is the vouch's.** After a vouch, the install's
  `version` and `installed_at` (on the pull, and in the signed payload) are
  the vouch event's sequence and time, not the unrecorded moment the pointer
  moved; and a healed kill-switch gap keeps the agent disabled but loses the
  flip's own record — `audit <run-id>` says "vouched for by", not "kill
  switch: disabled agent …". Keep your own note of what the flip was for.

## 5. Return the head

On success the command prints the ledger's new **head** — the hash of the latest
record. Save that hash somewhere off this machine (a chat, a ticket, a password
manager). Later you can hand it to `audit verify control --expect-head <hash>`
to prove the on-disk chain still ends exactly where you last saw it, closing the
gap that a purely local log can't close on its own.

## Applying over the API

`agenthof serve` exposes the same `apply` as `POST /v1/config/apply`. The
journey is the one above with two additions — a **precondition** on the
installed hash, and a **writer lock** that makes the whole sequence one
step with respect to every other writer:

```
  POST /v1/config/apply  {files: …}  If-Match: sha256:<installed>  |  If-None-Match: *
      │
      ▼
  1. Who?         the bearer token is verified → Invoker {subject, issuer, groups}
      │              (401 and nothing written if it is not; the witness is the server's)
      ▼
  2. May they?    take the writer lock; read the INSTALLED roles, bytes verified against the pointer;
      │              the ledger must vouch for that pointer
      │              not vouched → refused / not_on_record (recorded, with the proposal's hash, 403)
      │              then default-deny: no → refused / not_authorized (recorded, with the proposal's hash, 403)
      │              nothing installed and bootstrap not enabled → refused (recorded, 403)
      ▼
  3. Still true?  compare the installed hash to If-Match / If-None-Match
      │              no → 412 with the current hash (NOT recorded: no decision was made)
      ▼
  4. Valid?       stage the files, load, validate, hash
      │              no → rejected / validation_failed (recorded, with the copy's hash, 422)
      ▼
  5. Install      the copy becomes installed/<hex>/ and `current` points at it
      ▼
  6. Record       success (bootstrap when nothing was installed) + origin {via: api, …}
      │              release the lock
      ▼
  7. Answer       200 {config_hash, head, counts} + ETag — the next run executes it
```

Everything the record carries is what a command-line apply records, plus
`origin`: the way in. The witness on such a record is the serving host's OS
user and hostname — it corroborates nothing about the caller; the token
does that. Two outcomes are deliberately **not** recorded: a failed
precondition (`412`) and a busy lock (`409`) — in both, nothing was decided
and nothing was looked at. The vouch comes before the precondition, so a
caller whose `If-Match` is stale *and* whose server has an unvouched pointer
is answered `403` `not_on_record`, recorded — not `412`; `412` is reachable
only on a vouched pointer. A kill-switch flip on the host takes the same
lock, so an apply and a flip never interleave: the flip re-snapshots
whatever the apply installed, or the apply authorizes against whatever the
flip installed. `config vouch` takes it too, so a reader never sees a pointer
and ledger mid-vouch.

## Pulling the configuration

Execution points that are not the serving host need the law they are to
enforce. `agenthof config pull --server …` (or `GET /v1/config`) reads the
installed configuration back out of the control plane — authorized like
every control action, verified before it is served, and vouched for by the
ledger:

```
  GET /v1/config   (or /v1/config/hash for the hash, version and time alone)
      │
      ▼
  1. Who?         the bearer token is verified → Invoker {subject, issuer, groups}
      │              (401 and nothing read if it is not)
      ▼
  2. May they?    read the INSTALLED roles, bytes verified against the pointer; default-deny: pull, or apply, which includes it
      │              nothing installed → 404 · roles unreadable or bytes do not hash as the pointer → 500 · not granted → 403
      ▼
  3. The bytes    read the snapshot the pointer names and hash what was read:
      │              it must hash as the pointer, or nothing is served (500)
      ▼
  4. Vouched?     verify the control ledger and find the last install it recorded
      │              torn/broken → 500 · lock held → 503 retry
      │              last install ≠ the pointer → 503 "not yet on record; retry"
      ▼
  5. Answer       200 {hash, version, installed_at, files} + ETag — nothing recorded
```

`version` and `installed_at` are the ledger's own account of the install:
the sequence number and time of the last `apply`, kill-switch flip, or
`config vouch` that put a snapshot on record. The server answers `503` rather
than a snapshot the ledger does not vouch for — three situations produce it:
the moment inside every apply between the pointer moving and its record
landing (milliseconds); an install whose record was never appended
(`installed; event NOT recorded` — `config vouch` on the host clears it); and
a pointer re-aimed by hand at some other snapshot. The execution read holds
the same line, but definitively: `run` and `serve` read the pointer and the
ledger under a shared hold of the configuration lock, so they never meet the
first situation (an install in flight is waited for, or — past the lock
timeout — answered as a retryable busy, `serve` `503`, nothing recorded) and
refuse the other two as a **recorded** run refusal, `configuration not on
record`, until `config vouch` puts the install on record; a torn or broken
ledger refuses runs the same way, recorded with the repair hint, until it is
repaired. A ledger that was repaired still vouches — for the pull and for
runs: the taint is the audit readers' verdict about history, not about whether
the current pointer is on record.

A pull is a read: it is not recorded, and the server's log is the only
trace of who read the policy. What the puller then does is theirs: `config
pull --out <dir>` followed by `apply --config <dir>` on their own host is an
ordinary command-line apply there, recorded in that host's control ledger
under that host's rules, with the same hash the central ledger recorded. The
`pull` grant confines what an execution point may obtain from the server; it
says nothing about what its operator may do on their own machine.

The pulled files, and the hash, are the contract: `config pull` refuses a
pull whose files do not hash as the server said, before printing or writing
anything, and `--out` re-hashes the written directory.

A hash binds the files to what the server *stated*; a signature binds them to
who the operator *is*. Signing is opt-in. `config keygen` makes an Ed25519 pair
on the install host — the operator keeps the private key there, as they keep
the control ledger, and pins the public key at each execution point out of
band. With a key present, every install signs, over a payload that binds the
configuration hash to the control ledger's identity, the install's sequence,
and its time — so that, pinned to the public key, an execution point can tell
the configuration the operator installed, as a specific numbered install, from
an older one replayed or an impostor's. `serve` returns that signature on the
pull and verifies it against the bytes as it serves them: with a key
configured, it answers only when the control ledger vouches for the pointer
**and** a matching signature verifies; otherwise a retryable *not yet signed* —
usually the moment an install is ahead of its signature, but also whenever the
installed snapshot has no current signature (after `config keygen` on a
configuration installed earlier, or a removed or stale `.sig`), which `config
sign` clears. A broken key state — the public half missing or unreadable — is a
hard `500` instead, failing closed rather than dropping silently to unsigned.
With no key, nothing is signed and the transport and the token are the trust,
exactly as before. The signature is as strong as the custody of that private
key on the install host: it is evidence of origin, not a vault.

Where an execution point pins that public key — at `verify.pub` beside the
control ledger, or `agenthof run --verify-key <path>` — `run` and `serve` gate
on it: they verify the installed configuration's signature against the pinned
key **before executing it**, and refuse an unsigned, wrong-key, tampered,
replayed, or rolled-back install. A persisted `verify.floor` remembers the
highest `(log_id, version)` this point has verified, so an older signed install
cannot be rolled back under it (refused *stale*) and a different control ledger
is refused *foreign* until the floor is reset. The pinned check is layered on
the vouch every execution read performs: the pointer must first be the install
the control ledger records last (above), and only then are the signature and
the floor judged. The verify reads the pointer, the ledger and the signature
under one shared hold of the configuration lock — `installed.lock`, beside the
control ledger; a local `run` and `serve` open it, and on a fresh root create
it, so the control root must be writable by the user they run as — so it never
catches an install mid-write; a lock held past the timeout is a retryable
*busy*, not a refusal, and is not recorded. Pinning is opt-in and
fail-closed: with a key pinned, verification is mandatory. This is
tamper-evidence at the point of execution, with the same honest bound as the
ledger — it catches a tampered or partially-restored installed store, but a
restore of the whole control root carries the floor with it, so exclude
`verify.floor` from the backup set if it must survive one. The signature stays
with the root that made the install: `config pull` names the signer but writes
no signature, and an edge's own `apply` signs with the edge's key over the
edge's ledger — so today a point verifies installs made on its own root, and a
central operator key pinned at a pulling edge would refuse them. Carrying the
operator's signature to a pulled configuration, so the edge verifies *the
operator's* key, is reserved.

## 6. Reading it back

```
agenthof audit control                          # render the chain + an integrity line
agenthof config pull [--control-log <path>] [--out <dir>] [--json]   # the installed configuration, as it would be served
agenthof audit verify control [--expect-head H] # verify, and optionally check the head
agenthof audit repair control [--config <dir>]  # repair a torn tail (see below)
agenthof config vouch [--control-log <path>]    # put an unrecorded install on record (see "Recovering an unrecorded install")
```

Integrity is always stated, never assumed. Every read ends with a verdict:

- **verified** — the chain is intact and ends where expected.
- **torn** — the last record was cut off mid-write (a crash during append). The
  valid prefix still renders; only the torn tail is in question.
- **broken** — a link doesn't match: some earlier record was altered. The valid
  prefix before the break still renders.
- **tainted** — the chain verifies, but a `repair` record was appended at some
  point. Repair is legitimate and recorded, but it **permanently marks** the
  ledger so a reader knows a tail was once rebuilt. `audit verify control`
  reports this as its own exit status, distinct from clean.

This is **tamper-evident, not tamper-proof**: Agenthof cannot stop someone with
disk access from editing the file, but it makes any such edit *show* — the chain
breaks, or the repair that papered over it leaves a permanent taint. The limits
are the point, and they are documented rather than glossed over (Article I/III).

## The config_hash bridge to runs

The `config_hash` on an `apply` record is the seam that ties the control plane
back to the data plane. A run stamps the installed snapshot's hash, as the
installer recorded it; a control `apply` stamps the hash of the configuration it
adopted. Because both carry the same key:

- `agenthof audit <run-id>` prints a **config-join** line naming the install —
  the `apply`, the kill-switch flip, or the `config vouch` — that put the
  config a given run ran under on record — who applied (or vouched for) it,
  how, and when.
- `agenthof investigate` merges control actions and runs into one time-ordered
  timeline, so "someone disabled `coder`, then this run refused" reads as a
  single story. See [`reference/config.md`](reference/config.md) for the flags,
  exit codes, and the `investigate/1` JSON contract.

## What ships today vs what is reserved

| Shipped today | Reserved for later |
|---|---|
| `apply`, `registry enable/disable`, `audit repair control`, `gateway provision`, `runs prune`, `config vouch` | policy-as-config approval workflows |
| operator signing of the installed snapshot: `config keygen` mints the Ed25519 pair on the host, every install signs (opt-in), and `serve` returns the signature on the pull and verifies it as it serves — 200 only when the ledger vouches **and** a matching signature verifies, else a retryable *not yet signed*; `config sign` (re)signs an install; the public key is pinned at the edge | a recorded key-lifecycle event for rotation and revocation |
| `run` and `serve` verify the installed configuration against a pinned key (`verify.pub` / `run --verify-key`) before executing — unsigned/wrong-key/tampered/stale/foreign refused and recorded, a held lock a retryable busy, a persisted `verify.floor` bounding rollback; opt-in and fail-closed; Article VI names it | carrying the operator's signature with a pulled configuration so a consuming edge verifies the operator's key (today a point verifies only installs made on its own root); `--verify-floor` to relocate the floor outside a backup set; a `--max-age` bound on `installed_at` |
| `apply` over the API (`POST /v1/config/apply`) with a required compare-and-swap on the installed hash, authorization at the API against the installed roles, one writer lock across apply and the kill switch, and `origin` on the record; pulling the installed configuration over the API (`GET /v1/config`, `GET /v1/config/hash`, `config pull`), authorized by `pull` (or `apply`, which includes it), content-addressed, unrecorded | `registry enable\|disable` and `audit repair control` over the API; `audit control --server` |
| default-deny authorization of every control action against the `control:` grants of the **installed** configuration (what the last successful `apply` installed; the first apply bootstraps); the authorization read verifies the snapshot's bytes against the pointer and requires the control ledger to vouch for that pointer as its last install — an unvouched pointer is a recorded `not_on_record` refusal (`audit repair control` excepted: bytes verified, ledger not consulted); refusals recorded (repair: printed); `config vouch` puts an unrecorded install on record — bytes untouched, any identity, always recorded | per-object ownership; pruning of the snapshot store; a byte-verification verdict in `audit control` / `audit verify control` (today they compare pointer and ledger, never bytes); `config vouch` over the API |
| `run` and `serve` execute the installed configuration, resolved per run; nothing installed is a recorded refusal; the kill switch re-installs; the snapshot's bytes are verified against the pointer on the execution read, on the authorization read, and on the kill switch's re-snapshot read; the execution read executes only an install the control ledger records as its last (an `apply`, a kill-switch flip, or a `config vouch`) — a pointer it does not vouch for is a recorded refusal, a damaged ledger refuses runs until repaired, a held configuration lock a retryable busy | a warning at `apply` when it reverts a kill-switch flip; a disabled agent downing only the workflows that reference it; `registry list` over the installed snapshot |
| `gateway provision` and `runs prune` authorized against the installed roles (`provision`, `prune`) and recorded; prune spares the control ledger by name and by identity | `provision`/`prune` over the API; a structured prune record; `detail` in `investigate/1` |
| hash-chained control ledger with `seq`/`prev` + torn/broken/tainted verdicts; the `integrity.yaml` posture seam (floor only — a reserved posture is refused, never honoured) | external anchoring / write-once sink for the ledger (the seam ships; both tiers reserved) |
| three identities per action (invoker / asserted_as / witness) | agent-to-IdP federation for the invoker's authority |
| `--expect-head` off-machine head check | continuous/remote attestation of the head |
| `config_hash` join to runs (`audit <run-id>`, `investigate`) | SIEM export / multi-org investigation at scale |

Only shipped behavior is a guarantee.

## See also

- [`lifecycle.md`](lifecycle.md) — the life of a run (the data plane this governs).
- [`concepts.md`](concepts.md) — the pieces and why they're arranged this way.
- [`constitution.md`](constitution.md) — the invariants every action must honor.
- [`reference/config.md`](reference/config.md) — every control-plane flag and exit code.
