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

Eight commands write to the control plane — one of them, `apply`, can
also arrive over the network; one, `config vouch`, is a recovery act rather
than a change; and two change no configuration at all: `audit anchor` pins the
ledger's own head outside the machine, and `audit seal` closes the ledger's
active segment and opens the next:

```
agenthof apply --config ./config --as dana@example.com --groups platform-eng                   # adopt a configuration
agenthof registry disable coder --config ./config --as dana@example.com --groups platform-eng  # the kill switch: re-installs the configuration with coder disabled
agenthof registry enable  coder --config ./config --as dana@example.com --groups platform-eng  # …and back on
agenthof audit repair control --config ./config --as dana@example.com --groups platform-eng    # repair a torn ledger tail
agenthof gateway provision --as dana@example.com --groups platform-eng                           # mint provider keys for the installed roles
agenthof runs prune --older-than 180d --as dana@example.com --groups platform-eng               # remove aged run ledgers and artifact bodies
agenthof config vouch --control-log .agenthof/control.jsonl --as dana@example.com              # record the install event the ledger lacks for the snapshot already installed (recovery)
agenthof audit anchor --control-log .agenthof/control.jsonl --as dana@example.com --groups platform-eng  # pin the ledger's head into a transparency log (anchor: tlog) — see "The life of an anchor"
agenthof audit seal --control-log .agenthof/control.jsonl --as dana@example.com --groups platform-eng    # close the active segment into a sealed file and open the next — see "The life of a sealed segment"
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
  agenthof apply / registry enable|disable / audit repair control / gateway provision / runs prune / audit anchor / audit seal
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
any of `apply`, `enable`, `disable`, `repair`, `provision`, `prune`, `pull`, `anchor`, `seal`, named one by one, no wildcard —
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
control: [apply, enable, disable, repair, provision, prune, anchor, seal]
```

Four of the operations guard commands that change no configuration but are
control-plane actions all the same. `anchor` guards `audit anchor`, which pins
the ledger's head into a transparency log — see "The life of an anchor" below.
`seal` guards `audit seal`, which closes the ledger's active segment into a
sealed file and opens the next — see "The life of a sealed segment" below; the
same grant is needed to complete a seal that was interrupted. `gateway provision` mints a provider key
at the model gateway for every **installed** role that owns workflows — what
the last `apply` installed, never a directory — and records `provision`
with the installed configuration's hash; that record is not an install
(`audit verify control` and a run's config-join ignore it). `runs prune`
removes aged run ledgers and artifact bodies and records `prune` with a
one-line `detail` of what it removed and no hash: it installs nothing and
reads no configuration. All four refuse, recorded, when nothing is installed —
there are no roles to authorize against, and none of prune, anchor or seal has a
directory to fall back to (the kill switch and repair do, while nothing is
installed, because each has a directory in hand) — so after removing
`installed/current` a retention job, an anchoring cron or a sealing cron is
refused until the re-bootstrap apply lands. A provision
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
switch, `gateway provision`, `runs prune`, `audit anchor` and `audit seal` all require it. `audit repair
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
provision`, `runs prune` and `audit anchor` authorize against, only a snapshot the control
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
anchoring to a transparency log (`anchor: tlog`, `audit anchor`) proves to a
third party. Two narrower limits are worth naming. `audit control` and `audit verify control` compare the pointer
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
- **One chain, however many files** — a ledger that has been sealed (`audit
  seal`) is an ordered set of sealed segments plus the live active segment,
  and `seq`, `prev` and the genesis `log_id` carry straight across the file
  boundaries: the append always lands on the chain's logical position, and the
  readers walk the whole set as one chain. A never-sealed ledger is the one
  file described above, byte for byte. See "The life of a sealed segment".

The record is a **control/1** event: `{ action, outcome, invoker, asserted_as,
witness, config_hash, seq, prev, … }`. The `outcome` is one of `success`,
`rejected`, `refused`, or `error`, and **all four are recorded** — the ledger is
a log of *attempts*, not only of successes.

**Honest limits.** There are four narrow cases the ledger names rather than
hides. If the ledger is already **torn or broken** when a command runs, the
command records nothing new, exits non-zero, and tells you to run `audit repair
control` first — a damaged chain is not appended to. A ledger whose **seal has
not finished rotating** is refused the same way, by every writer, with a
different remedy: nothing is recorded and the command names `audit seal`, which
completes the rotation (reads and runs are not held up; see "The life of a
sealed segment"). And a `registry`
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
the ledger (absent means the default: the local hash-chained file this section
describes — sink `local`, anchor `none`). Setting `anchor: tlog` turns on
external anchoring: `agenthof audit anchor` pins the current head into the
transparency log the posture names — an authorized `anchor` control action,
recorded as its own `anchor` event — and `audit verify control` checks every
recorded anchor against the chain, failing (exit 6) only on a head the chain no
longer reproduces, or a stored proof that fails under a key that verified, and
reporting an unreachable log or a rotated key as unverifiable (exit 7), never
as tampering. Setting `sink: worm` is honoured too: `audit seal` then
writes each sealed segment's exact bytes to the write-once sink the posture
names (S3 Object Lock, compliance mode) and does not complete until that copy
is confirmed (the life of a sealed segment, below). A posture naming
a still-reserved sink or anchor (`external`, `signed`) is one the build
cannot honour, so every control write — `apply`, a `registry` flip, `config
vouch`, `gateway provision`, `runs prune`, `audit repair control`, `audit
anchor`, `audit seal` — refuses before it opens the ledger, and `serve` refuses to start; a running server
keeps the posture it read, so a change takes effect on restart. The `anchor`
record was reserved by the schema before it was ever written; a root without
`anchor: tlog` configured still never writes one.

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
agenthof audit verify control [--expect-head H | K:H] [--anchor-key <path>] [--offline]   # verify, check the head, check every recorded anchor
agenthof audit repair control [--config <dir>]  # repair a torn tail of the active segment (see below)
agenthof config vouch [--control-log <path>]    # put an unrecorded install on record (see "Recovering an unrecorded install")
agenthof audit seal [--if-larger-than <size>]   # close the active segment and open the next (see "The life of a sealed segment")
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

On a ledger that has been sealed, the verdict is over the whole set: one
`segment k:` line per sealed segment precedes the events, the integrity line
counts the sealed segments, and a fault in any segment — or between two — is
named with its global `seq` and its own remedy. A seal whose rotation did not
finish is reported as its own state, not as damage: `audit control` prints the
state line and still exits 0, `audit verify control` exits 8 for it, last in
precedence behind every integrity verdict. See "The life of a sealed segment".

This is **tamper-evident, not tamper-proof**: Agenthof cannot stop someone with
disk access from editing the file, but it makes any such edit *show* — the chain
breaks, or the repair that papered over it leaves a permanent taint. The limits
are the point, and they are documented rather than glossed over (Article I/III).

## The life of an anchor

The chain above shows when a record was edited *in place*. It cannot, on its
own, show that the whole file was regenerated or its tail cut off: that takes
a head held somewhere the writer of this file cannot reach — which is why §5
asks you to save the head off the machine. `anchor: tlog` makes that a
recorded, repeatable act. `agenthof audit anchor` pins the ledger's current
head into a **transparency log** the operator names — an append-only log
outside this machine's trust domain, that hands back a proof that the head was
entered — and
records on the ledger itself which head was pinned, where the log put it, and
the log's own proof. This section follows one anchor from the head to the
verdict a later reader gets. Everything in it ships today unless marked
reserved.

```
  integrity.yaml beside the ledger:   anchor: tlog
                                      anchor_backend: { kind: transparency-log, url: https://<the log you name> }
      │
      ▼
  agenthof audit anchor            (a cron, with --token; or an operator at the terminal)
      │
      ▼
  1. Who? / May they?    authenticate ──► the installed snapshot's bytes, the ledger's vouch, then
      │                   default-deny on the role grant `anchor`  ──► no ──► refused (recorded; no network)
      ▼
  2. The head            read and verify the chain  ──►  Head { seq=K, sha256=H_K }
      │
      ▼
  3. Submit              sign H_K with a fresh throwaway key; POST the entry to the log
      │                   ◄── the log answers: entry id, inclusion proof, signed checkpoint
      │                   verify that proof here, under the log's key, BEFORE anything is recorded
      │                   any failure ──► anchor / error (recorded, with what it tried to cover); ledger otherwise untouched
      ▼
  4. Record it           append anchor / success { seq=K, hash=H_K, kind, backend, ref, proof, backend_key_id }
      │
      ▼
  5. Ship the line       anchored: seq=K sha256=H_K      ◄── a verifier input; save it off the box
      │
      ▼
  6. Verify later        agenthof audit verify control [--expect-head K:H_K] [--anchor-key <log key>] [--offline]
                           the chain must still reproduce H_K at seq K, and the stored proof must verify
                           under the pinned log key  ──►  verified | MISMATCH (exit 6) | unverifiable (exit 7)
```

### Naming the log

The posture lives in `integrity.yaml` beside the control ledger — operator
written, never written by Agenthof. `anchor: tlog` turns anchoring on, and
`anchor_backend.url` names the log; **there is no default endpoint**, so
nothing is ever published to a service you did not name (the Sigstore
public-good log is one choice; a log you run yourself is another — see the
bounds below). `kind` defaults to `transparency-log`, the only kind this build
accepts (`rfc3161` is reserved and refused by name), and an
optional `credential` is a broker reference — environment-variable *names* for
a direct bearer or a `client_credentials` grant, never a value; the public-good
log needs none. The file is checked for shape only: the first contact with the
log is the command. Every other writer — `apply`, the kill switch, `config
vouch`, `gateway provision`, `runs prune`, `audit repair control`, `audit seal`, `serve` —
reads a `tlog` posture and proceeds exactly as at the floor, unanchored;
**nothing anchors but `audit anchor`**. The reference for every field is in
[`reference/config.md`](reference/config.md).

### Who, and may they?

`audit anchor` is a control action, not a maintenance script, and it is
treated like every other one in this document. The invoker is resolved as
§1 above describes (`--as`/`--groups`, or a verified `--token`), and the
command answers the same questions in the same order: the posture is read
first (a file that cannot be read or does not validate exits 2; a root without
`anchor: tlog` exits 1 — both before anything is recorded and without touching
the network); the ledger must be writable (busy or damaged exits 1,
unrecorded); a token that fails verification is recorded as `refused`; and
then the authorization read of §2 above runs under a shared hold of the configuration lock —
the installed snapshot's bytes verified against the pointer, the control
ledger required to vouch for that pointer as its last install, and the
invoker's groups checked, default-deny, against a role that grants `anchor`.
Nothing installed, an unvouched pointer, and a caller no role grants are each
a **recorded refusal** — and each stops before any network call, so a refused
caller never causes an entry in a public log.

### The head

The lock is released and the chain is read and verified once more; the head
that comes back — `seq=K` and the SHA-256 of record K's exact bytes, `H_K` —
is what gets anchored. The hash *is* the anchored object: the log is handed
the digest and nothing else, never the record's bytes. An empty ledger has no
head and exits 1, unrecorded. Because the record will name `(K, H_K)`
explicitly, the head is free to advance under the command: an anchor pins the
head that was read, not whatever is current when the record lands.

### Submit, and verify the answer before trusting it

Agenthof generates a fresh ECDSA P-256 key, signs `H_K` with it, and posts
the entry — the digest, the signature and the key's public half — to the log.
That key lives for the length of the call and is then dropped; it is never
stored. **It proves nothing.** It exists because this kind of log requires an
entry to carry a signature; the lift comes from the log's *inclusion* of the
digest, not from who signed it (Article III says the same).

The log answers with an entry id, an inclusion proof (the Merkle path from
the entry to the log's root) and a signed checkpoint (the root, the tree
size, the log's signature over them). Agenthof verifies that answer **before
returning anything**: the entry the ref locates names `H_K`; the checkpoint
opens under the log's key; the checkpoint names the
entry's tree and the proof's root and size; and the inclusion proof verifies.
Which key is "the log's key" is the operator's call: with `anchor.pub`
present beside the ledger, the checkpoint must open under *that* pinned key
and the command refuses a log presenting any other; without it, the key the
log serves for the entry's tree is used and its id recorded, and the printed
line says `as served` — trust in the log's own word, not yet independent
verification. The proof is also size-capped so that a record can never carry
an oversized one.

A failure anywhere here — the log unreachable or slow past `--timeout`, any
answer but *created*, a proof that does not verify or is over the cap, a key
other than the pinned one, a credential the broker could not resolve — is
recorded as an `anchor` `error` (reason `anchor_failed`) that names what it
tried to cover (the seq, the hash and the log), and the command exits 1. **A
backend failure never blocks or corrupts the ledger**: the ledger is otherwise
untouched, every other writer keeps working, and the next tick simply tries
again. No success record ever carries a proof that did not verify at anchor
time.

### Record it

The success is one `control/1` record, `action: anchor`, under the three
identities of §1 above, whose `anchor` payload carries:

| field | what it is |
|---|---|
| `seq`, `hash` | the covered head, `(K, H_K)` — the chain must reproduce this hash at this position |
| `kind` | which knob produced it: `tlog` |
| `backend_kind`, `backend` | the proof format (`transparency-log`) and the log's URL as configured, so a verifier reads the record alone and never `integrity.yaml` (which may have changed since) |
| `ref` | the log's entry id — a locator, so anyone can find the entry in the log |
| `proof` | the entry body as the log served it, the inclusion path, and the signed checkpoint — everything a verifier needs, stored **on the record** so the anchor verifies offline, for as long as the record exists, outliving the log's read API |
| `backend_key_id` | the identity of the log key that signed the checkpoint — forensic, not protective: it records which key the log presented, so a later change is visible; only a key *you* pin protects |

Nothing in it is a secret, and none of it is a configuration: an anchor
carries no `config_hash`, is never an install, and no reader treats it as one
(`audit <run-id>`'s config-join and the vouch ignore it). The append is held
to a permit — a successful anchor must say what it covers, the covered seq
must exist in the chain (judged under the writer lock, so it holds even if
the head advanced), the proof must fit the cap — so a malformed anchor
appends nothing. `audit control` renders it as `head anchored: seq K <hash>
(tlog)`; a failed attempt renders as `anchor error`.

One gap is named rather than hidden, as in §4 above: if the log took the entry
but the record could not be appended, the command prints `anchored at <ref>
but NOT recorded` and exits 1. That entry is harmless — a public digest with
nothing pointing at it — and the next run records a new one.

### Ship the line

On success the command prints, in this order, `anchored: seq=K sha256=H_K`,
the log, the entry id and the log key (with `pinned` or `as served`), the
log's own index and integration time *as reported by the log* — Agenthof
verifies the proof, never the time — and finally the new control head. The
`anchored:` line is the artifact: it carries exactly the two values
`audit verify control --expect-head <seq>:<hex>` takes — hand them back as
`K:H` — so a cron that ships it off the box every tick leaves a trail of heads
that the box cannot rewrite.

### Verify later

`audit verify control` checks every anchor the chain records, after it has
verified the chain itself, and prints one line per anchor and a summary
(`anchors: N (v verified, m mismatch, u unverifiable)`; `anchors: none` when
there are none). Each anchor is judged in two steps:

1. **Against the chain** — from the records alone, no posture, no network:
   the record must carry a payload, the covered seq must come before the
   record, and the chain must reproduce the recorded hash at the recorded
   position. Editing or deleting `integrity.yaml` cannot silence an anchor
   the chain carries.
2. **Against the log** — from the stored proof, under a key the verifier
   trusts. The key is `--anchor-key <path>`, else `anchor.pub` beside the
   ledger, else — unpinned — the key the log serves for the entry's tree,
   which must have the id the record names. The proof is verified **offline
   first**, exactly as at anchor time; only then, unless `--offline`, the log
   is asked whether the entry is still there — a courtesy to the operator,
   **never what makes an anchor verified**: it can only tighten a verified
   anchor into a mismatch (a 200 with a different body), never produce a pass;
   any failure to answer, a *not found* included, is reported as unverifiable
   with *proof verified offline; presence not checked*.

The verdicts are kept honestly apart, and the exit codes never fold one into
the other:

- **exit 6, mismatch** — only for a definitive content disagreement: the
  chain no longer reproduces a recorded head (a rewritten root), or, under a
  key that verified, the stored entry names another hash, the proof or the
  checkpoint does not hold, or the log serves a different body for the
  recorded entry.
- **exit 7, unverifiable** — no verdict could be reached and none mismatched:
  the log unreachable; a key the verifier does not hold (the pinned key is not
  the one that signed; the served key is not the one recorded at anchor time);
  `--offline` with no key pinned; a key file missing or malformed; a proof
  format or backend kind this build does not read. **A log that is down, a
  rotated key, or a missing pin is never tampering** — the line names the fix
  (pin a key, update `anchor.pub`, retry) and every definitive verdict outranks
  it in the exit precedence.

Both are in the exit-code table in [`reference/config.md`](reference/config.md).

`agenthof investigate` shows the same thing in its timeline, so an incident
read does not need a second command: every `anchor` event that recorded what
it tried carries its facts (the covered `seq:hash`, the log, the entry; a
refused attempt recorded none) and, on a success record, the verdict
`audit verify control --offline` reaches under the same pin — `verified`,
`mismatch` or `unverifiable` — from the records alone, **offline** under the
pinned key (`anchor.pub` beside the ledger, or `--anchor-key`; over `serve`,
the server's own `anchor.pub`), with the cause when not verified; the trailer
`anchors: N (v verified, m mismatch, u unverifiable)` follows the integrity
line, and `--json` carries it as `anchor.verdict` on the event. It is
informational: `investigate` never asks the log, and its exit code and
`integrity.ok` say what the chains' bytes say, not what the anchors say —
`audit verify control` is the gate (exits 6 and 7). Without a pin nothing
reads `verified`: every anchor the chain still reproduces is `unverifiable`.
The fields are in
[`reference/config.md`](reference/config.md) under *Anchors in the timeline*.

A verifier on **another machine** needs three things, none of them from the
box under suspicion: a copy of the ledger, the `anchored: seq=K sha256=H_K`
line it shipped earlier, and the log's public key obtained from the log's own
trust root. Then `audit verify control --control-log <copy> --expect-head K:H_K
--anchor-key <log key> --offline` answers from the proofs on the records with
no network at all (a bare copy of the ledger, with no `installed/` beside it,
gets no pointer verdict — there is no pointer to compare): exit 6 if an anchor
the copy carries no longer matches the chain or its proof fails under the key;
exit 4 if the copy does not reproduce `H_K` at `K` and carries no anchor for
it — a root rewritten from scratch; 0 if every anchor stands.

### Honest bounds

What an anchor proves is bounded, and the bounds are the point (Article III):

- **Between anchors, the head rests on the chain alone.** Records appended
  after the last anchor are evidenced only by their hash links until the next
  one. Cadence is the operator's: `audit anchor` is run from a cron (or by
  hand), and nothing in `serve` or any other writer anchors on its own.
- **A rewrite that drops the anchor records reads `anchors: none`.** The
  verifier checks the anchors the chain *carries*; a root regenerated from
  scratch carries none. That rewrite is caught by the `anchored:` line held
  off the box (`--expect-head K:H`), or by anyone who finds the entry in the
  log and asks the box to reproduce its head — which is why the line is
  printed and why the entry is findable in the log.
- **"Independently verifiable" has a condition.** The verdict is the stored
  proof under a key the verifier trusts. A verifier that takes the log's key
  from the log, or the log's address from the root it is verifying, trusts what
  it was handed and is not independent — which is why the record's `backend`
  URL drives only the non-load-bearing presence check and the unpinned
  served-key fetch, and why `--anchor-key` exists: the lift is a key pinned
  off the box.
- **The ephemeral entry key proves nothing** beyond the log's requirement for
  one; the log's inclusion is the evidence. The log's integration time is
  reported, not verified.
- **A public log is public.** What it exposes is opaque: the hash of one
  ledger record, and when it was entered — never a record's content, never a
  configuration, never an identity. If even the timing of your control
  changes is sensitive, run a log of your own in a different trust domain —
  it is that separation from the box, not publicity, that makes a log a
  witness — or wait for the reserved timestamp-authority backend.
  Which log, and therefore which trust, is yours to choose by the `url` you
  name.

### Shipped today vs reserved

Shipped: `anchor: tlog` with a `transparency-log` backend, `audit anchor`,
the `anchor` record with its proof, `audit control`'s rendering of it, and
`audit verify control`'s per-anchor verdicts with `--expect-head K:H`,
`--anchor-key`, `--offline` and `--anchor-timeout`, and the anchor facts and
offline verdict on `anchor` events in `investigate`'s timeline and
`investigate/1` document, locally and over `serve`; and, beside the anchor,
the `sink: worm` posture — a protected copy of each sealed segment, described
with the life of a sealed segment below. Reserved, and refused by name today
if you write them: an RFC 3161 timestamp-authority backend (`kind: rfc3161`),
the `sink: external` storage sink and `anchor: signed`. Reserved, and simply
not there yet: a periodic or `serve`-driven cadence. Only shipped behavior is
a guarantee.

## The life of a sealed segment

Everything above treats the control ledger as one file. A ledger that is
appended to for years is still one *chain*, but it need not stay one *file*:
`agenthof audit seal` closes the active file into a **sealed segment** and
opens a fresh, empty active beside it. After a few seals the ledger is an
ordered set of sealed segments plus the live active — read, verified and
appended as **one logical chain with one sequence**, so nothing a reader
learned above changes: `seq` keeps counting, every `prev` still names the line
before it (across the file boundary too), and the genesis `log_id` stays the
ledger's identity for its whole life. A segment is a unit you can copy, hash,
ship off the box and compare — the chain that was already there, cut at
recorded points. This section follows one segment from the seal that closes it
to the reads that walk it later. Everything in it ships today unless marked
reserved; a ledger that is never sealed is the single file the rest of this
page describes, byte for byte.

```
  .agenthof/control.jsonl                              one file, seq 1..B — "the active"
      │
      ▼
  agenthof audit seal [--if-larger-than 50m]           (a cron, with --token; or an operator at the terminal)
      │
      ▼
  1. Who? / May they?    authenticate ──► the installed snapshot's bytes, the ledger's vouch, then
      │                   default-deny on the role grant `seal`  ──► no ──► refused (recorded)
      ▼
  2. Worth sealing?      --if-larger-than: the active is not larger ──► printed, exit 0, nothing recorded
      │                   an empty active ──► nothing to seal, exit 1, nothing recorded
      ▼
  3. Link               control.jsonl.seg-000001  ──►  a second name for the SAME file (a hard link)
      ▼
  4. Record             append seal / success { segment: 1, first_seq: 1, head_seq: B, head_hash: H_B, content_sha256 }
      │                   as seq B+1 — the segment's last line; the chain's head is now this line
      │                   (sink: worm: the record also carries a sink block — kind, url, key, mode: compliance, retain_until)
      ▼
  4b. Protected copy    sink: worm only — the sealed file's exact bytes ──► the sink, at the key the record names,
      │                   locked compliance to at least retain_until; the lock is read back ──► confirmed
      │                   not confirmed ──► the seal stands, the manifest is NOT written; the next audit seal completes it
      ▼
  5. Manifest           control.jsonl.segments  ◄── written whole: temp, fsync, rename  (segment 1: seq 1–B+1, sha256 of the file)
      ▼
  6. Swap               control.jsonl  ──►  a fresh, empty file under the active's name
      │                   the old bytes live on under .seg-000001 alone
      ▼
  7. Ship the line      protected: s3-object-lock <url> key=<key> version=<id> compliance until <date>   ◄── sink: worm only
                        sealed: segment 1 seq=1..B+1 sha256=<file> (control.jsonl.seg-000001)
                        control head: seq=B+1 sha256=<the seal line>        ◄── save these off the box
      │
      ▼
  8. Carry on           the next apply is seq B+2, prev = the seal line's hash, in the new active
                        audit control / verify control / investigate / serve read .seg-000001 + control.jsonl as one chain
```

### Who, and may they?

`audit seal` is a control action and is treated like every other one on this
page. The invoker is resolved as §1 describes; the posture is read first (a
file that cannot be read or does not validate exits 2, unrecorded); the set
must be writable (busy exits 1 unrecorded; a torn or broken active prints the
repair hint); a token that fails verification is recorded as `refused`; and the
authorization read of §2 runs — the installed snapshot's bytes verified against
the pointer, the ledger required to vouch for that pointer, the invoker's
groups checked, default-deny, against a role that grants `seal`. Nothing
installed, an unvouched pointer and a caller no role grants are each a
**recorded refusal**, written to the active that stays open. The seal holds
the configuration lock *exclusively* for its whole run, so no install is ever
caught between its pointer move and its record by a rotation.

`--if-larger-than <size>` (bytes; `k`, `m`, `g`) is for a cron: judged
**after** authorization, so every refusal is still recorded and an authorized
no-op leaves no record at all — the command prints that the active is not
larger and exits 0. An empty active is never sealed (a segment holding only
its own seal would record nothing), and the filesystem must make hard links;
one that cannot is told so and nothing is recorded.

### The seal, in four steps

The four steps run in a fixed order under the active's exclusive lock, and the
order is what makes an interruption safe:

1. **Link.** The active is hard-linked under its segment name,
   `<log>.seg-NNNNNN` (six digits; `N` is one more than the segments already
   sealed). The file now has two names and no byte has moved. Beside a
   symlinked `--control-log`, the segments and the manifest are created beside
   the file the link resolves to.
2. **Record.** A `seal` `success` record is appended as the segment's **last
   line**, under the three identities of §1. Its payload names exactly what it
   closes: `segment`, `first_seq` and `head_seq` (the segment's first and last
   record *before* the seal), `head_hash` (the record before it — its own
   `prev`) and `content_sha256` (every byte of the segment before this line).
   The append is held to a permit: the payload must describe precisely the
   active this writer holds, so a seal can be written by nothing but a seal
   of this very segment. This is the first commit: **the segment is closed.**
3. **Manifest.** `<log>.segments` is rewritten whole — a temp file, fsynced,
   renamed over the old one, the directory fsynced — now listing the new
   segment: its file name, `first_seq`, `head_seq` (the seal line included),
   `head_hash` (the seal line's hash — the next segment's starting `prev`),
   the whole file's `sha256`, its byte size and the seal's time. This is the
   second commit: **the set is rotated.**
4. **Swap.** A fresh, empty file is put under the active's name (temp, fsync,
   rename, directory fsync). The sealed bytes now live under the segment name
   alone.

On a `sink: worm` root one more step sits between **Record** and
**Manifest**: the sealed file's exact bytes are written to the sink the record
names and the copy is *confirmed* before the manifest lists the segment.
[The protected copy](#the-protected-copy--sink-worm) below follows it; the
four steps above are unchanged by it.

The command then prints `sealed: segment N seq=A..B sha256=<file> (<name>)`
and the head, which is the seal line itself. Both are verifier inputs: the
`sha256` is the whole sealed file as the manifest records it, and `B:<head>`
is exactly what `audit verify control --expect-head <seq>:<hex>` takes, so a
cron that ships the two lines off the box every rotation leaves a trail of
cut points the box cannot rewrite. `audit control` renders the record as
`segment N sealed (seq A–B)` — the range of the records it closes, one short
of the `sealed:` line's range, which includes the seal line itself.

**The manifest is advisory.** It is an index, not an authority: every value in
it is recomputed from the files on every read, and a disagreement refuses the
read naming the field (`head_seq 40 recorded, 41 verified`). A manifest from
another ledger is refused outright — its `log_id` must be the genesis's. An
operator who loses it can rewrite it from `audit verify control`'s per-segment
lines; the chain is the record.

### Reading across the boundary

Every reader — `audit control`, `audit verify control`, `investigate`, the
vouch that `run`, `serve` and every control command perform, the pull, and the
server's `/audit` and `/v1/investigate` — reads the set the same way: the
manifest, then each sealed segment in order (its chain verified from the
previous segment's head, its last record required to be its own seal and
nothing to follow it, every manifest figure recomputed), then the active,
verified from the last sealed head. The result is one list of records, one
head, and one verdict. A reader holds the active's shared lock and a seal
needs the exclusive one, so a reader always sees one consistent set and never
a rotation half-done.

Appending is the mirror image: a writer walks the sealed segments without
the lock (nothing writes a sealed file), then locks the active by name,
confirms the manifest did not change under it, and appends at the chain's
logical position — the next `seq`, `prev` the last line wherever it is. An
anchor's coverage is judged against that same logical count, so anchors
recorded before a seal keep verifying after it and a new anchor may cover the
seal line itself.

The verdicts are the ones §6 lists, over the whole set. A torn or broken
**active** is `torn` or `broken` with its global `seq`, exactly as before. A
fault anywhere else is named for what it is and exits 1 from `audit verify
control` (`investigate` folds it into `broken`): a sealed segment torn or
broken in the middle (*a sealed segment is never repaired in place; restore it
from a copy*, with the expected `sha256`); a segment whose first record does
not chain from the previous head (*altered, replaced or reordered*); a segment
the manifest lists that is gone; a `.seg-*` file the manifest does not list;
a manifest that disagrees with its files; a seal that is not its segment's
last record; a root with sealed history whose active file is gone (never
"nothing recorded yet"). Each line names the segment, the global `seq` and
the remedy.

**One hazard is operational and named by its cause.** A binary older than
sealing, pointed at a root that has sealed, opens the empty active after a
rotation and — knowing nothing of the segments beside it — mints a fresh
genesis there. The next read by a current binary reports it distinctly: *its
first record is a fresh genesis … a writer older than this root's seals wrote
it* — with the remedy: upgrade every binary that shares the root, move that
active aside (its records are evidence, not chain) and create an empty one in
its place; the chain continues from the last sealed head. **The standing rule
is to upgrade every binary that shares the control root before the first
seal, and never run an older one against it afterwards.**

### An interrupted rotation

A crash can fall between any two of the four steps, and the seal is built so
that each landing is a state the next run finishes, not a fault to diagnose:

| the crash fell after | what is on disk | what happens next |
|---|---|---|
| the **link**, before the record | an open active with a second name beside it | nothing is owed: appends continue; the next `audit seal` finds the link already pointing at the same file and continues from there |
| the **record**, before the manifest | the active's last line is a successful seal; the manifest does not list it yet | the segment is closed; the set is **not yet rotated** |
| the **record**, before the protected copy is confirmed (`sink: worm`) | as above, and the seal names a sink key that holds no confirmed copy yet — nothing, or an unconfirmed write | the same state: closed, **not yet rotated**; the next `audit seal` confirms the copy before it writes the manifest — writing it, or finding the seal's own bytes already at the key and confirming them without writing again (`(already confirmed)`) |
| the **manifest**, before the swap | the manifest lists the segment; the active's name still refers to the sealed file | the set is rotated; the fresh active is **not yet in place** |

In the last three states the ledger is *sealed and not yet rotated*. Reads are
unaffected — the chain is whole and verifies, `audit control` prints
`control ledger: segment N sealed, rotation not completed; run: agenthof audit
seal` and exits 0, `investigate` reads `verified`, and `run` and `serve` keep
executing (the vouch is a read). **Writes refuse**: every control writer —
`apply`, the kill switch, `config vouch`, `gateway provision`, `runs prune`,
`audit anchor`, `audit repair control` — records nothing and names `audit seal`
as the remedy; over the API, `POST /v1/config/apply` answers `500`
`{status:"rotation_incomplete"}` with a fixed body, nothing recorded, and the
server's log names the command. `audit verify control` exits **8** for it —
*rotation not completed* — the last code in its precedence (1, 6, 9, 3, 4, 5,
7, 10, 8), so a tamper, a protected-copy verdict or an unverifiable anchor on
the same root is what you see first; the chain itself is intact. Running
`agenthof audit seal` **completes** the rotation: it takes the same
authorization (the `seal` grant; a refused completion is printed, not
recorded, because the closed segment takes no record and the next does not yet
exist), skips `--if-larger-than`, redoes whichever of link, protected copy
(on a `sink: worm` root), manifest and swap is missing — each step is harmless
to repeat — and
prints `completed rotation of segment N` before the usual `sealed:` line. A
seal that fails at the manifest or the swap says so on the spot (`sealed;
rotation NOT completed — re-run: agenthof audit seal`), and one whose
protected copy could not be confirmed says so too (`sealed; protected copy NOT
confirmed — rotation NOT completed; re-run: agenthof audit seal`); nothing is
lost.

### Repairing the active, and only the active

`audit repair control` reads the whole set and decides from the verdict. It
recovers two shapes, both in the **active** segment, and in both the damaged
bytes are moved aside to a `<log>.torn-<timestamp>` fragment — the only
remaining copy, kept indefinitely, never pruned — before anything is cut:

- **A torn tail with no seal before it** — the case §6 describes: the tail is
  moved aside, the active truncated to its last valid record, and a chained
  `repair` record appended on the chain's position. The ledger is tainted from
  then on.
- **Bytes after a seal line** — a seal that recorded but whose rotation did not
  finish, and then something landed after it: a torn write, or whole records
  (a writer older than this root's seals appended to a closed segment; the
  verdict reads *seal record … is not its last record*). Everything after the
  seal line is moved to the fragment, the active is truncated at the end of the
  seal line, the rotation is **completed** — the same link, manifest and swap —
  and the `repair` record is appended as the **new active's first record**, its
  `prev` the seal line's hash. The command prints `rotation of segment K
  completed`; the ledger is tainted all the same.

Everything else is refused with its own remedy and nothing changes. A seal that
is simply not yet rotated, with nothing after it, is `audit seal`'s to
complete — *not a repair matter*. A chain break mid-active is not a tail to cut
off. A fault in a **sealed** segment is never repaired in place: a sealed
segment is the unit a copy exists of and the boundary every later segment
chains from, so the remedy is to restore it from a copy whose `sha256` matches
the manifest. A missing, unexpected or disagreeing segment or manifest names its
own fix. And a ledger whose genesis predates `log_id` — written before ledgers
carried an identity — **cannot be sealed at all**: the manifest requires the
identity, so `audit seal` refuses before anything is linked or recorded, and the
root remains a single, writable file; no remedy is invented, because none exists
short of editing the ledger.

### The protected copy — `sink: worm`

Everything above happens on one machine, in files whoever owns the host can
rewrite. Where the control root's `integrity.yaml` declares `sink: worm` —
`sink_backend` naming an S3-compatible bucket with Object Lock, compliance
mode, and a retention period (the shape is in
[`reference/config.md`](reference/config.md)) — every seal **also writes the
sealed segment's exact bytes to that bucket**, under a compliance-mode
retention lock the storage provider enforces, and the seal does not complete
until that copy is confirmed. That copy is the **protected copy**. This
subsection follows it from the seal that writes it to the reads and
recoveries that use it. It ships today; the bounds at the end are part of
the description, not a footnote.

```
  agenthof audit seal                                    on a root whose integrity.yaml says sink: worm
      │
      ▼
  preflight            the credential resolves; the bucket answers and has Object Lock enabled;
      │                 the seal's own key holds no version   ──► else refused: nothing linked, nothing recorded
      ▼
  link, record         steps 3–4 above; the seal record carries a sink block:
      │                 { kind: s3-object-lock, url, key: <prefix>/<log_id>/seg-000001, mode: compliance, retain_until }
      ▼
  protected copy       PUT the sealed file's exact bytes at the key, locked COMPLIANCE to at least retain_until
      │                 read back: the version is the OLDEST at the key and its lock holds to at least that date  ──► confirmed
      │                 anything less ──► the seal stands, the manifest is not written; the next audit seal completes it
      ▼
  manifest, swap       steps 5–6 above — so a segment the manifest lists has a confirmed copy, or carries no block
      ▼
  later                audit verify control      record ──► sink (each copy)   and   sink ──► local set (each object)
                       audit restore control     one damaged sealed segment back from its copy, selected by the chain
                       audit restore control --rebuild --log-id <id>   the whole sealed set and its manifest, from the sink alone
```

**Where the copy goes is decided before the seal line is written.** The key
is derived from two things only — the ledger's `log_id` and the segment's
ordinal, under the prefix the URL names: `<prefix>/<log_id>/seg-000001` — so
one bucket may hold many ledgers and each key is one segment's and no other's.
The seal record carries a **sink block** naming the sink's kind and URL as
configured, that key, `mode: compliance`, and `retain_until`: the seal's time
plus the configured retention, the *floor* the copy's lock must hold to. All
of it is on the chain; the upload's outcome is not — that is the sink's own
state, which every reader checks by asking the sink. Never a credential, a
signed URL or a receipt.

**Preflight, before anything is linked or recorded.** The credential must
resolve (the environment variables the posture names), the bucket must answer
and report Object Lock enabled (versioning is implied), and the seal's own key
must hold no version. A key already occupied refuses the seal with nothing
linked and nothing recorded, naming the two things it can mean — this ledger
sealed this segment before and the local set no longer lists it (the sink
still holds the original: run `audit verify control`, then `audit restore
control --rebuild`), or a foreign object sits at the key — and that a
compliance-locked version cannot be removed either way.

**The copy, confirmed.** After the seal record — the segment is closed — the
sealed file's bytes are written at the key with the lock headers: compliance
mode, locked to the later of the recorded `retain_until` and now plus the
retention (a provider refuses a lock date in the past, so a seal left
incomplete past its own retention still completes; the read-back still holds
the lock to the recorded date). *Confirmed* means three things the sink
itself reports: it minted a version id (none means versioning is off and
nothing was locked), that version lists as the **oldest** at the key, and its
retention reads back as compliance to at least the recorded date. Only then
is the manifest written. That ordering is what makes the manifest a
confirmation: **a segment the manifest lists has a confirmed protected copy**,
or its seal record carries no sink block. The command prints `protected:
s3-object-lock <url> key=<key> version=<id> compliance until <date>` before
`sealed:` — the version the sink confirmed and the lock as the sink reports
it, never shorter than the record's date, often longer — and `audit control`
renders the seal with `→ protected copy <kind> <url> until <date>`.

**Not confirmed: fail-closed, nothing lost.** The sink unreachable or slow, a
credential that can write but not read back, no version id, another writer
landing a version at the key between the empty listing and the write — each
leaves the seal record standing and the manifest unwritten: the ledger is
*sealed and not yet rotated*, exactly the state the table above describes,
every control writer refuses, `audit verify control` exits 8, and the
command says `sealed; protected copy NOT confirmed — rotation NOT completed;
re-run: agenthof audit seal`. The re-run completes it: it lists the key, and
where every version there holds this segment's bytes — the oldest under a
sufficient lock — it confirms the oldest without writing again (`(already
confirmed)`); an empty key is written; a key holding any version that is not
this segment is refused, whatever else sits there. **The seal never writes on top of a version that is
not this segment** — the oldest version at a key is always the seal's own, by
construction, which is what lets every reader judge the oldest and only the
oldest. A foreign version at the key blocks that key: an unlocked one a
credential with delete may remove before the re-run; a compliance-locked one
until its retention ends. Rewriting `integrity.yaml` is not an escape: a seal
recorded for a copy completes only through a sink of the same kind and URL,
at the key that sink derives for this ledger's segment.

**Verify, in both directions.** After the chain pass, `audit verify control`
on a sealed root asks the sink about every copy. *Record → sink*: for each
sealed segment whose seal names a sink block, it lists the key — no version
is `MISSING`; reads the oldest version whole and compares the bytes with the
local file — other bytes is `LOCAL MISMATCH` (the local file was altered; a
later version that happens to match is not the copy, because the seal wrote
the oldest); and reads the lock — unlocked, governance, or compliance ending
before the recorded date while that date has not passed is `UNDER-LOCKED`.
*Sink → local set*: it lists the ledger's prefix, and every object there must
be the copy of a local segment that carries a block and whose copy was not
just found altered; an object at an ordinal the local set does not account
for — a segment the local set lost or replaced, or one past its last segment
— is named with `audit restore control --segment N` as the remedy (a seal
that lands while the verification runs is judged again against a fresh read
of the ledger and reported as in flight, never as a verdict). Any one of
those is a **definitive** verdict: exit **9**. Anything the verifier could
not decide — the sink unreachable, slow or refusing (`status 403 … from
<host> (<operation>)`), half an answer, a posture it cannot read, a record
naming a sink other than the posture's — is **unverifiable**: exit **10**,
reported as exactly that and never as tampering. Both sit in the precedence
where they belong (1, 6, 9, 3, 4, 5, 7, 10, 8): a definitive copy verdict is
outranked only by a chain fault and an anchor mismatch, and an unverifiable
copy is reported just after an unverifiable anchor — never ahead of a
definitive verdict of any kind. A segment sealed before the root declared the
sink prints `protected copy: none (sealed before sink: worm)`; `--offline`
skips the pass and says so. One more honesty: the posture read from beside
the ledger names the sink's address from the root being verified, and the
summary says so (*not independent; pass `--integrity`*) — a copy of
`integrity.yaml` held off the box is the independent input.

**Repair confirms before it cuts.** On a `sink: worm` root, the repair case
that completes a rotation — bytes after a seal line — confirms the protected
copy *first*, on the bytes the chain fixes (the records through the seal
line), and only then moves the tail aside and truncates; the torn-tail case
never touches the sink. A sink that cannot confirm leaves the ledger exactly
as it was found, torn and nothing owed; a retry writes the same bytes to the
same key. A sink outage during a repair changes nothing locally.

**Restore one segment.** `audit restore control [--segment N]` runs under the
`repair` grant and answers one kind of fault: a sealed segment the manifest
lists that is missing, torn, broken, does not chain from the segment before
it, or disagrees with its manifest entry. It reads the versions at that
segment's key oldest first and selects **by the chain, never by the
manifest**: the version is sealed segment N whose records chain from the
previous segment's head (the genesis for segment 1), whose last line is a
seal that recomputes as segment N and names this key, and whose seal line is
what the next segment's first record — or the active's — chains from. The
manifest's `sha256` is a cross-check only. Every sink call runs before the
ledger is locked; a lock that cannot be read back fails closed with nothing
written. Then, under the active's exclusive lock, whatever bytes sit under
the segment's name are moved aside as `<log>.replaced-NNNNNN-<timestamp>` —
never deleted; they are the evidence of what was there — the fetched bytes
are written (temp, fsync, rename), the set is read again and must verify
clean, and a `restore` `success` record is appended under the invoker's three
identities. It prints `restored: segment N from <kind> <url> version=<id>
sha256=<file> (<replaced name>)` — `(nothing was there)` when the file was
missing — and tells you when the version it selected is not the oldest at the
key, or is not under a compliance lock. A restore **taints nothing**: nothing
is truncated, and every byte it writes is one the chain already commits to.
No version at the key chains: *the protected copy is missing*, nothing
written.

**Rebuild the whole set.** `audit restore control --rebuild --log-id <id>`
is for a root whose sealed files and manifest are gone, damaged beyond the
manifest, or tidied short — the ledger's identity is in the `protected:`
line's key (`<prefix>/<log_id>/seg-N`) shipped off the box with each seal, on
`audit control`'s header, on the ledger's genesis record (`log_id`), and in the
bucket listing itself,
where it is the folder every segment sits under. It lists the
ledger's prefix (every key must be a segment's; the ordinals must run 1..N
without a gap — *a chain with a hole cannot be reconstructed*), fetches each
ordinal's oldest version and verifies
the **entire chain** link by link, genesis to the last seal, **before
anything is written**; any failure refuses the whole rebuild and nothing
local changes. Then it writes, ascending: a local file byte-identical to the
copy is left alone, a differing one moved aside as evidence and rewritten, an
absent one written; the manifest is recomputed from the fetched bytes (the
old one kept as `<log>.replaced-segments-<timestamp>` when it differed); an
empty active is created when none exists. The set is read again, and one
`restore` record says what was verified, written and replaced — appended even
when nothing needed writing, because a set verified against the sink is a
visible act. It prints `rebuilt: segments 1–N from <kind> <url> (W written,
R replaced)` with the names kept, and names any copy whose lock is weaker
than its seal recorded (reported, not refused — the bytes are still the
chain's). A rebuild never completes a rotation, and a present active that no
longer chains from the rebuilt head is named with its remedy, not cut. One
limit, stated: a rebuild holds the fetched set in memory while it verifies —
bounded, and sized for control-ledger segments.

**What the protected copy is, and is not** (Article III):

- **It covers sealed segments, from the seal that writes it, and nothing
  else.** The active segment, every local file — the segments, the manifest,
  the active — and any segment sealed *before* the root declared the sink are
  ordinary files with no protected copy. Declaring `sink: worm` on a root
  that has already sealed protects the seals from then on; the earlier ones
  print `protected copy: none`.
- **Within the retention period the copy cannot be deleted, altered or
  shortened by any storage operation, whoever issues it, the account's owner
  included.** The provider's one escape is closing the account, which is
  outside Agenthof's view and is not silent. The words write-once and
  non-erasable describe that copy alone, for that period alone — never a
  sealed file, never the ledger.
- **The guarantee is the provider's compliance mode, not Agenthof's.**
  Agenthof does not run the lock; it asks for it, reads back what the
  provider reports, and refuses to call anything less *confirmed*. That is
  why `mode: governance` is refused in the posture (a privileged user can
  lift it), why the lock is read back rather than assumed, and why a sink
  that cannot be asked is *unverifiable*, never *verified*.
- **It catches a consistent rewrite of the whole local set only where the
  rewritten set no longer accounts for what the sink holds.** A sealed file
  replaced under its name is caught byte for byte against the oldest version;
  a sealed segment dropped from the local set is caught by the object the
  sink still holds. A rewrite that keeps every sealed file exactly as it was
  and rewrites the active alone is not the sink's to catch — that is the
  anchored head's, checked against a reference held off the machine
  ([the life of an anchor](#the-life-of-an-anchor)). The two layer.
- **A credential that can write can still write more.** Further versions on
  top of a key and delete markers on it are possible for anyone who can write
  to the bucket; neither touches the locked oldest version, which is the one
  every verifier judges, and both are reported as information (*later
  versions differ: written over, the protected copy stands*).
- **Availability is the cost, never integrity.** A sink that is down blocks
  the next seal's completion and makes `audit verify control` exit 10; it
  never produces a wrong verdict, and reads of the ledger continue.
- **When the retention period ends, the copy is a file like any other.** The
  verdict says so (`unlocked — verified; the retention period ended …`), and
  says `expiring` as the end approaches. Retention is the operator's choice
  in the posture; nothing here extends it.

### Honest bounds

What a sealed segment is, and is not (Article III):

- **A sealed segment is a regular file.** Whoever owns the host can still
  rewrite it, as they could the single file before. Sealing moves no byte and
  adds no protection; what it adds is a *unit* — a closed range of the chain
  with a recorded cut point, a recorded hash of its bytes, and a fixed name —
  that can be copied, compared and later pinned.
- **The chain detects a dropped, duplicated, reordered or inconsistently
  edited segment, not a consistent rewrite of the whole set.** A segment
  removed, swapped in order or edited without recomputing everything after it
  breaks a boundary or a manifest figure and is named. A rewrite of every
  segment, the manifest and the active together, consistently, is the same
  rewrite the single file always allowed — caught by a head held off the box
  (`--expect-head B:<head>` from the `sealed:` output) or by an anchor (`audit
  seal --if-larger-than 50m && audit anchor` anchors each rotation's final
  head), never by the files alone.
- **The manifest proves nothing.** It is recomputed on every read; it speeds
  nothing up and it cannot vouch for a file. The seal records and the hash
  links are the evidence.
- **Nothing is pruned.** Every sealed segment is kept in full, indefinitely,
  as the compliance record. A retention rule over sealed segments is reserved
  (the manifest reserves the keys for it and refuses them today).
- **Under `sink: worm`, the protected copy is the one exception, and it is
  bounded.** The copy — not the sealed file — is non-erasable for the
  retention period, on the strength of the provider's compliance mode; the
  local files stay regular files, and the bounds above apply to them
  unchanged. [The protected copy](#the-protected-copy--sink-worm) states
  its own.

### Shipped today vs reserved

Shipped: `audit seal` with `--if-larger-than`, the `seal` control operation
and record, the `<log>.seg-NNNNNN` segments and the advisory `<log>.segments`
manifest, reading and appending across the set as one chain in every reader
and writer (the CLI and `serve`), completion of an interrupted rotation by the
next `audit seal`, `audit verify control`'s per-segment lines and exit 8,
`audit repair control`'s completion of a rotation that had bytes after its
seal, the distinct cause for an older binary's fresh genesis, and — under
`sink: worm` — the seal's protected copy of each sealed segment, written to
S3 Object Lock storage under a compliance-mode retention lock and confirmed
before the rotation completes, `audit verify control`'s verdict on every copy
in both directions (exit 9 definitive, exit 10 unverifiable), `audit repair
control` confirming the copy before it cuts, `audit restore control` to put a
damaged sealed segment back from its copy, and `audit restore control
--rebuild --log-id <id>` to reconstruct the whole sealed set and its manifest
from the sink; the active segment and every local file stay ordinary files,
and the copy is protected for the retention period alone, by the provider's
compliance mode. Reserved: pinning the whole ledger into a non-erasable `sink: external` storage sink
(refused by name today), pruning sealed segments under a retention rule, and
sealing a ledger whose genesis carries no `log_id`. Only shipped behavior is a
guarantee.

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
| `apply`, `registry enable/disable`, `audit repair control`, `gateway provision`, `runs prune`, `config vouch`, `audit anchor`, `audit seal` | policy-as-config approval workflows |
| operator signing of the installed snapshot: `config keygen` mints the Ed25519 pair on the host, every install signs (opt-in), and `serve` returns the signature on the pull and verifies it as it serves — 200 only when the ledger vouches **and** a matching signature verifies, else a retryable *not yet signed*; `config sign` (re)signs an install; the public key is pinned at the edge | a recorded key-lifecycle event for rotation and revocation |
| `run` and `serve` verify the installed configuration against a pinned key (`verify.pub` / `run --verify-key`) before executing — unsigned/wrong-key/tampered/stale/foreign refused and recorded, a held lock a retryable busy, a persisted `verify.floor` bounding rollback; opt-in and fail-closed; Article VI names it | carrying the operator's signature with a pulled configuration so a consuming edge verifies the operator's key (today a point verifies only installs made on its own root); `--verify-floor` to relocate the floor outside a backup set; a `--max-age` bound on `installed_at` |
| `apply` over the API (`POST /v1/config/apply`) with a required compare-and-swap on the installed hash, authorization at the API against the installed roles, one writer lock across apply and the kill switch, and `origin` on the record; pulling the installed configuration over the API (`GET /v1/config`, `GET /v1/config/hash`, `config pull`), authorized by `pull` (or `apply`, which includes it), content-addressed, unrecorded | `registry enable\|disable` and `audit repair control` over the API; `audit control --server` |
| default-deny authorization of every control action against the `control:` grants of the **installed** configuration (what the last successful `apply` installed; the first apply bootstraps); the authorization read verifies the snapshot's bytes against the pointer and requires the control ledger to vouch for that pointer as its last install — an unvouched pointer is a recorded `not_on_record` refusal (`audit repair control` excepted: bytes verified, ledger not consulted); refusals recorded (repair: printed); `config vouch` puts an unrecorded install on record — bytes untouched, any identity, always recorded | per-object ownership; pruning of the snapshot store; a byte-verification verdict in `audit control` / `audit verify control` (today they compare pointer and ledger, never bytes); `config vouch` over the API |
| `run` and `serve` execute the installed configuration, resolved per run; nothing installed is a recorded refusal; the kill switch re-installs; the snapshot's bytes are verified against the pointer on the execution read, on the authorization read, and on the kill switch's re-snapshot read; the execution read executes only an install the control ledger records as its last (an `apply`, a kill-switch flip, or a `config vouch`) — a pointer it does not vouch for is a recorded refusal, a damaged ledger refuses runs until repaired, a held configuration lock a retryable busy | a warning at `apply` when it reverts a kill-switch flip; a disabled agent downing only the workflows that reference it; `registry list` over the installed snapshot |
| `gateway provision` and `runs prune` authorized against the installed roles (`provision`, `prune`) and recorded; prune spares the control ledger by name and by identity | `provision`/`prune` over the API; a structured prune record; `detail` in `investigate/1` |
| hash-chained control ledger with `seq`/`prev` + torn/broken/tainted verdicts; `anchor: tlog` external anchoring of the head (`audit anchor` pins it into a transparency log, `audit verify control` checks every recorded anchor — exit 6 only for a genuine content mismatch (a head the chain no longer reproduces, or a proof that fails under a verified key), exit 7 when unverifiable; a still-reserved sink or anchor — `sink: external`, `anchor: signed` — is refused) | a non-erasable storage sink for the whole ledger (`sink: external`) and `anchor: signed` |
| sealing and rotating the control ledger: `audit seal` closes the active segment into a sealed file (`<log>.seg-NNNNNN`) and opens the next, recorded as an authorized `seal` action and listed in an advisory `<log>.segments` manifest; the segments and the active read, verify and append as one chain with one `seq`; an interrupted rotation is completed by the next `audit seal`, never left broken (`audit verify control` exit 8 while it is owed); `audit repair control` recovers a torn tail of the active and, when bytes landed after a seal, moves them aside and completes that rotation — a sealed segment is never repaired in place; `--if-larger-than` for a cron; a never-sealed ledger is unchanged; `sink: worm`: each seal also writes the sealed segment's exact bytes to S3 Object Lock storage (compliance mode) and does not complete until the copy is confirmed — the seal record names the copy and its lock date, `audit verify control` fails on a copy that is missing, under-locked or holds other bytes (exit 9; unreachable is exit 10, never tampering), `audit restore control` puts a damaged sealed segment back from it and `--rebuild --log-id <id>` reconstructs the whole sealed set and its manifest from the sink; the active and every local file stay ordinary files | pinning the whole ledger into a non-erasable `sink: external` storage sink; pruning sealed segments under a retention rule (the manifest reserves the keys); sealing a ledger whose genesis predates `log_id` (refused today, single file) |
| three identities per action (invoker / asserted_as / witness) | agent-to-IdP federation for the invoker's authority |
| `--expect-head` off-machine head check | continuous/remote attestation of the head |
| `config_hash` join to runs (`audit <run-id>`, `investigate`) | SIEM export / multi-org investigation at scale |

Only shipped behavior is a guarantee.

## See also

- [`lifecycle.md`](lifecycle.md) — the life of a run (the data plane this governs).
- [`concepts.md`](concepts.md) — the pieces and why they're arranged this way.
- [`constitution.md`](constitution.md) — the invariants every action must honor.
- [`reference/config.md`](reference/config.md) — every control-plane flag and exit code.
