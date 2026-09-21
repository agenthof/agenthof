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

Three commands write to the control plane:

```
agenthof apply --config ./config --as dana@example.com          # adopt a configuration
agenthof registry disable coder --config ./config --as dana@example.com   # the kill switch
agenthof registry enable  coder --config ./config --as dana@example.com   # …and back on
agenthof audit repair control --as dana@example.com             # repair a torn ledger tail
```

Each one is an *attempt* to change governance state, and each attempt — whether
it succeeds, is rejected, or is refused — is recorded to a single, append-only,
hash-chained **control ledger** (`.agenthof/control.jsonl`). The control plane's
promise is not that nothing bad can happen; it is that **nothing happens without
a record you can later verify**.

## The journey at a glance

```
  agenthof apply / registry enable|disable / audit repair control
      │
      ▼
  1. Who is changing it?   authenticate  ──►  Invoker {subject, issuer, method}
      │                                        + asserted_as (claimed) + witness (machine)
      ▼
  2. Is the change valid?  validate  ──►  no ──►  rejected / refused  (recorded, then stop)
      │ yes
      ▼
  3. Record it            open the Locked ledger, append a control/1 event:
      │                     { action, outcome, invoker, witness, config_hash, seq, prev }
      │                     outcome ∈ success | rejected | refused | error — ALL recorded
      ▼
  4. Return the head       print the new chain head (a hash) — save it off-machine
      │
      ▼
  5. Read it back          agenthof audit control        ──► the story, in order
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

## 2. Is the change valid?

What "valid" means depends on the action:

- **`apply`** builds and validates the whole configuration (roles, workflows,
  agents, gateway) before adopting it. A configuration that fails validation is
  recorded as **`rejected`** (reason `validation_failed`) — together with the
  hash of the config that was rejected, so you can see exactly *what* was turned
  away.
- **`registry enable|disable`** checks that the named agent exists; an unknown
  agent is recorded as `refused` (reason `agent_not_found`) — `rejected` means a
  change was evaluated and turned down, while `refused` means the actor or target
  wasn't admitted in the first place.

Either way the outcome is written down. A turned-away change is a governed event,
not an error swallowed at the door.

## 3. Record it on the chain

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

**Honest limits.** There are two narrow cases the ledger names rather than
hides. If the ledger is already **torn or broken** when a command runs, the
command records nothing new, exits non-zero, and tells you to run `audit repair
control` first — a damaged chain is not appended to. And a `registry`
flip that lands but whose recording append then fails prints `state changed;
event NOT recorded` — the one case where state changed with no event to show for
it. Both are surfaced loudly; neither is glossed over.

## 4. Return the head

On success the command prints the ledger's new **head** — the hash of the latest
record. Save that hash somewhere off this machine (a chat, a ticket, a password
manager). Later you can hand it to `audit verify control --expect-head <hash>`
to prove the on-disk chain still ends exactly where you last saw it, closing the
gap that a purely local log can't close on its own.

## 5. Reading it back

```
agenthof audit control                          # render the chain + an integrity line
agenthof audit verify control [--expect-head H] # verify, and optionally check the head
agenthof audit repair control                   # repair a torn tail (see below)
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
back to the data plane. A run stamps the hash of the configuration it executed
under; a control `apply` stamps the hash of the configuration it adopted. Because
both carry the same key:

- `agenthof audit <run-id>` prints a **config-join** line naming the `apply` that
  put the config a given run ran under — who applied it, how, and when.
- `agenthof investigate` merges control actions and runs into one time-ordered
  timeline, so "someone disabled `coder`, then this run refused" reads as a
  single story. See [`reference/config.md`](reference/config.md) for the flags,
  exit codes, and the `investigate/1` JSON contract.

## What ships today vs what is reserved

| Shipped today | Reserved for later |
|---|---|
| `apply`, `registry enable/disable`, `audit repair control` | policy-as-config approval workflows |
| hash-chained control ledger with `seq`/`prev` + torn/broken/tainted verdicts | external anchoring / write-once sink for the ledger |
| three identities per action (invoker / asserted_as / witness) | agent-to-IdP federation for the invoker's authority |
| `--expect-head` off-machine head check | continuous/remote attestation of the head |
| `config_hash` join to runs (`audit <run-id>`, `investigate`) | SIEM export / multi-org investigation at scale |

Only shipped behavior is a guarantee.

## See also

- [`lifecycle.md`](lifecycle.md) — the life of a run (the data plane this governs).
- [`concepts.md`](concepts.md) — the pieces and why they're arranged this way.
- [`constitution.md`](constitution.md) — the invariants every action must honor.
- [`reference/config.md`](reference/config.md) — every control-plane flag and exit code.
