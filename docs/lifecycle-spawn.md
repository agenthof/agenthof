# The life of a spawn

One governed child run, from the moment an agent asks for it to the ledger
lines it leaves behind. This is the spawn door. For the run it happens
inside, see [`lifecycle.md`](lifecycle.md). For the YAML, see
[`may_spawn`](reference/config.md#may_spawn),
[`spawn`](reference/config.md#spawn) and
[`spawn_supervisor`](reference/config.md#spawn_supervisor). For the
executable proofs, see [`scripts/e2e-spawn-local.sh`](../scripts/e2e-spawn-local.sh)
(the door, the ledger and the supervisor protocol, with no container
runtime) and [`scripts/e2e-spawn.sh`](../scripts/e2e-spawn.sh) (real
compartments and real isolation, with rootless podman). For the supervisor
itself, [`deploy/refspawn/README.md`](../deploy/refspawn/README.md).

```
  agent (parent run, depth d)   Agenthof                       refspawn (host)              ledgers
    |  POST /spawn                 |                                |                           |
    |  {role, workflow, input}     |-- on may_spawn? caps? -- no -------------------------------> parent: spawn refused
    |                              |      | yes                     |                           |
    |                              |-- pre-run gate ------- no ---------------------------------> child: run_refused
    |                              |      | yes                     |                           |
    |                              |-- provision {child id,         |                           |
    |                              |     the workflow's agents} --->| volume + 1 compartment    |
    |                              |                                |   per agent, all on /work,|
    |                              | <-- {child dir, agent sockets, |   + 1 refexec on it       |
    |                              |      exec socket}  (held open) |                           |
    |                              |   none? ----------------------------------------------------> parent: spawn refused
    |                              |-- run the child workflow against those sockets:            |
    |                              |     registry gate ---- no ---------------------------------> child: run_refused
    |                              |     steps, doors, ... (its exec door -> the child's refexec)| child: workflow_started ... workflow_finished
    |                              |-- close the held request ----->| SIGTERM refexec, rm the   |
    |                              |                                |   compartments, rm volume |
    | <-- {status, child_run_id,   |-- after the child is over --------------------------------> parent: spawn {child_run_id, status, output_sha}
    |      output_sha, preview}    |                                |                           |
```

## When the door exists

Every fronted step has a per-run listener, and `/spawn` is one of its
routes. Whether the door does anything is decided by config: an agent may
spawn only the `{role, workflow}` pairs listed under its
[`may_spawn`](reference/config.md#may_spawn), and an agent with no list
spawns nothing. Declaring `may_spawn` anywhere makes two more things
required at `apply`: the gateway's [`spawn`](reference/config.md#spawn) caps,
and a [`spawn_supervisor`](reference/config.md#spawn_supervisor) — the
operator-side runtime that gives each child compartments of its own. A
config that grants spawning without bounding it, or without somewhere to
run a child, is rejected.

## The request

The agent POSTs `{"role", "workflow", "input"}` to `<proxy-url>/spawn` with
the run token as a bearer, exactly as it reaches the other doors. The call
is synchronous: it returns when the child run is over, so it holds the
parent step's connection for the child's whole duration. Nothing else is
needed — no credential, no run id, no identity claim. The parent's binding
comes from the gateway itself, never from the request body, so an agent
cannot spawn as anyone but the human who invoked it.

## What Agenthof checks before anything starts

Three gates, each recorded when it refuses:

1. **Is the target on this agent's `may_spawn` list?** Exact match on both
   role and workflow. No: a `spawn` event with status `refused` on the
   parent's ledger and a `403`.
2. **Is there room under the caps?** The run's depth rides its binding (a
   root is 0). A child that would sit deeper than `max_depth`, a run that
   already has `max_parallel` children in flight, or a run that has already
   used up `max_total_spawns` over its life is refused the same way. The
   check and the reservation are one atomic step, so N simultaneous
   requests cannot each see room for one more.
3. **Does the child need a verified human?** A workflow whose agents reach
   an on-behalf-of resource is refused before anything is provisioned when
   the invoker has no verified token, exactly as at the command line. This
   child gets a ledger of its own with one `run_refused` event carrying its
   parent linkage.

There is one refusal that is not recorded: a request that arrives after the
parent step is already over is answered `503` — the run's ledger may
already be closed.

## Where the child runs

A child does not run beside its parent. Before the child's workflow starts,
Agenthof asks the supervisor named by `spawn_supervisor` — the reference
one is `refspawn`, a host process like Agenthof that invokes podman — for an
isolated set, naming the child's run id and the distinct agents its
workflow's steps use. The supervisor creates:

- **one workspace volume** for the child, mounted at `/work`;
- **one refbox compartment per agent** in the child's workflow, each
  running the image the supervisor's config maps that agent to — no
  network, a read-only root, every capability dropped, resource caps — all
  mounting that one volume, and reaching Agenthof only through the child's
  own socket directory, which is mounted into those compartments and no
  others;
- **one `refexec` process** for the child, bound to the same volume, so the
  child's first-hand exec runs against the child's files.

The supervisor answers only once every socket in the set accepts a
connection; Agenthof then runs the child's workflow against those sockets.
Each step is dialed at its agent's compartment, and the child's exec door
goes to the child's refexec, whatever `endpoint:` or `exec.url:` the agents'
YAML names — under spawn, the supervisor's sockets win. The child's own
per-step gateway listens in the child's socket directory, so a grandchild
can be asked for only from inside the child.

**Within one child, its agents share the child's `/work` on purpose.** A
workflow's steps run one at a time and pass their work along it — the
writer writes, the reader reads — the same rule a root run follows.
**Between runs, nothing is shared.** Two children spawned in parallel get
two volumes; a child and its parent never see each other's files; a
child's exec socket sits in a directory that is never mounted into any
compartment, so a child agent reaches exec only through the governed door.

If any of this cannot be had, the spawn is refused with the fixed reason
`spawn compartment unavailable`, recorded on the parent's ledger, and the
child is never run anywhere else:

- no supervisor is configured, it is unreachable, or its socket sits behind
  a directory that is not private to the user Agenthof runs as;
- the supervisor has no image for an agent in the child's workflow, or its
  own compartment cap would be exceeded;
- a compartment fails to start, or never answers within the supervisor's
  readiness window;
- the answer would place the child's exec socket inside the child's own
  mounted directory, or either of the child's directories inside the socket
  directory mounted into the compartments of the run that asked. That last
  check is made by the spawning run at every depth, against the directory
  actually mounted into *its* own compartments.

One reason covers all of them on purpose: an agent learns nothing about the
operator's runtime from a refusal. Which one it was is in the operator's
log.

## The child run

A child is a full governed run. It gets its own run id (the supervisor's
compartments and volume are named for it), its own hash-chained ledger in
the same run-log directory as the parent, and its own per-run gateway. Its
binding is `{invoker: the parent's, unchanged; role; workflow; run_id;
parent_run_id: the parent's; depth: the parent's + 1}`, and it rides every
event the child records. Its identity half reaches the agent as the usual
`X-Agenthof-*` headers on each step — invoker, issuer, method, role,
workflow, and `X-Agenthof-Run-Id` for the child's own run; the parent
linkage lives on the ledger, not in a header. The binding is forwarded, not
signed. It passes the same registry gate a root run passes — the role
must exist, own the workflow, and admit the invoker's groups. A child
refused at that gate still gets a ledger with one `run_refused` event; its
compartments were already provisioned and are torn down like any other.

A child may spawn in turn, within the caps: `max_depth` bounds how deep,
`max_parallel` how wide at each node, `max_total_spawns` how many over each
node's life. The whole tree under one root is bounded by the sum over
k = 1..`max_depth` of `max_total_spawns`^k. Parallelism is the agent's
choice: it issues several `/spawn` calls at once.

## What counts

`max_total_spawns` counts children whose compartments were provisioned. A
refusal at the door, a pre-run refusal, and a failed provision start
nothing and give the reservation back; a provisioned child counts whatever
happens next — even a registry refusal. The supervisor's own
`max_compartments` is a separate backstop on how many agent compartments
may be alive across every child at once.

## Teardown

The held provision request is the child's lifeline: Agenthof closes it when
the child is over, and the supervisor then removes the set in order — the
child's refexec first (it removes any exec compartment it still holds),
then the agent compartments, then the volume, then the directories. The
volume is removed without forcing, so the removal succeeding is itself the
evidence that nothing still mounts the child's workspace. If anything in
the set dies first, the supervisor ends the request from its side, and
Agenthof cancels the child rather than let it wait for a socket that will
never answer.

The child runs under the parent step's context. When the parent step ends —
it finished, it timed out, or the agent hung up — every in-flight child is
cancelled with it, its set torn down, and its children with them. A
cancelled child stops between steps with `workflow_finished`
`status: cancelled`, which the parent's `spawn` event records as `failed`;
a child cut in the middle of a step records that step failed. Teardown is
bounded, not instant.

The whole subtree under one step shares that step's deadline. It is one
knob, [`step_timeout`](reference/config.md#step_timeout): it bounds the
engine's step, the request Agenthof makes to the agent, and the time
provisioning may take. Size it for the subtree a spawning step will build,
and set the supervisor's compartment `timeout` at or above it — the
supervisor has its own config and cannot see Agenthof's value.

## The record

Two nodes, one event each, no double counting:

- On the **parent**, one `spawn` event after the child is over:
  `{type: "spawn", agent, status: succeeded | failed | refused, child_run_id,
  child_role, child_workflow, depth, output_sha, reason}`. `child_run_id`
  is present whenever a child ledger exists — including a child refused at
  its registry gate or before its engine started — and absent when the
  door or the supervisor refused before one existed. `output_sha` is the
  hash of the child's final artifact; the artifact body never crosses back
  onto the parent's ledger (the agent receives a capped preview).
- On the **child**, its own full trail, every event carrying
  `parent_run_id` and `depth` on its binding; its `exec` events carry the
  child's refexec's first-hand account.

`agenthof audit <parent-id>` renders the spawn line; `agenthof audit
<child-id>` renders the child like any run. `agenthof investigate --run
<id>` shows the run **and every run spawned under it**, each child's lines
indented under its parent with a `parent=<run-id>` tag; `--json` carries
`parent_run_id` and `depth` on each record.

## Cycles

A "cycle" can only exist at the type level — an agent whose `may_spawn`
reaches, through some workflow's steps, an agent that can reach it back.
Every run is a fresh node, so no run is ever its own ancestor, and
`max_depth` bounds any such reuse. With `spawn.reject_cycles: true`,
`apply` rejects a config whose spawn graph has a cycle, self-loops included;
because `may_spawn` fully determines what can be reached, that static check
is complete, and there is no runtime check.

## Limits, stated plainly

- **Isolation is per child, through the operator's supervisor.** Agenthof
  itself still runs nothing and isolates nothing: the compartments and the
  volume are the supervisor's, and the root run's own containment remains
  the operator's deployment choice (`deploy/refbox`) — the root's workspace
  is whatever the operator mounted. What Agenthof guarantees is that a
  child runs only where the supervisor put it, or not at all.
- **A child's own agents are not isolated from each other.** They share one
  workspace by design, so nothing in `/work` is protected between them: one
  agent can read, overwrite, or follow a symlink another left behind. The
  boundary spawn draws is between runs, not within one.
- A child always starts on a fresh, empty workspace and hands back only a
  hash and a preview. Handing a child a shared or persistent workspace is
  not supported.
- If `agenthof` is killed outright, its held requests close and the
  supervisor tears the children down. If the supervisor is killed outright,
  the children live until podman's timeout trips, or until the next
  supervisor starts and reaps them by name.
- A `/spawn` is synchronous and holds the parent step's connection for the
  child's duration, bounded by the step timeout.
- The invoker propagates unchanged; there is no separate acting-agent
  identity on the child's binding.
- The binding is forwarded, not signed.
- The cycle guard is static and optional; depth bounds everything else.

## See also

- [`lifecycle.md`](lifecycle.md) — the life of a run, which every child is.
- [`lifecycle-exec.md`](lifecycle-exec.md#the-first-hand-door) — the first-hand exec door a child's refexec serves.
- [`agent-protocol.md`](agent-protocol.md#spawn-door--a-governed-child-run) — the wire shape.
- [`reference/config.md`](reference/config.md#may_spawn) — `may_spawn`, `spawn`, `spawn_supervisor`, `step_timeout`.
- [`deploy/refspawn/README.md`](../deploy/refspawn/README.md) — the reference supervisor.
