# The life of a grounded answer

One question about your meeting notes, from the command you type to an answer
that came out of those notes and a receipt that says what the run actually did.
Two halves make the journey: first the notes are **indexed** into a governed
memory store, then questions are **answered** from what the store holds.

Nothing here is a new mechanism. The agents are ordinary
[enrolled](lifecycle-enroll.md) agents, routed by the [`ask`](lifecycle-ask.md)
orchestrator, run as contained [spawns](lifecycle-spawn.md), and reaching the
model and tools only through the [model door](lifecycle-model.md) and the
[tool door](lifecycle-tool.md). This page follows one question across those
pieces and adds only what is particular to retrieval: what the three agents do,
what the receipt can honestly say about a retrieved answer, and where that
stops. For how `ask` classifies, confirms, and builds its receipt in general,
read [`lifecycle-ask.md`](lifecycle-ask.md); it is not repeated here.

The three agents live in the public agent hub (`rag-ingest`, `rag-retrieve`,
`rag-research`), each with a README of its own. The engine knows nothing special
about them: it sees agents with a model grant, an embeddings grant, and tool
grants, like any other.

## The command

An operator installs the agents once, [enrolling](lifecycle-enroll.md) each from
its signed card, defining the gateway resources they name (a `memory` tool
resource, a `drive` tool resource, an `embed` embeddings model, a `chat` model),
listing the agents in the orchestrator's `may_spawn`, and stamping each agent's
[`grounding`](reference/config.md#grounding). The grounding is the operator's
declaration, set after enrolling, never something the card can claim for
itself.

After that there are two paths, both through the same command.

Indexing, the write path:

```
agenthof ask "index my meeting notes"
```

Asking, the read path:

```
agenthof ask "what did we decide about entitlement revocation?"
agenthof ask "how is a JWT normally verified, and what did we agree?"
```

`ask` classifies the prompt against its menu and runs exactly one of the three
agents. The prompt picks the path; the agents do not call each other.

| Agent | Job | Declared grounding | Chat call |
| --- | --- | --- | --- |
| `rag-ingest` | read notes from Drive, write them into the memory store | unset | none |
| `rag-retrieve` | answer only from the stored notes | `grounded` | one (none if nothing is found) |
| `rag-research` | answer from the stored notes plus the model's own knowledge | `mixed` | one |

## The journey at a glance

```
  INDEXING                                      ASKING

  agenthof ask "index my notes"                 agenthof ask "<question>"
        |                                             |
        v                                             v
  ask routes to rag-ingest                      ask routes to rag-retrieve
  (read-write grant: CONFIRM, or --yes)         or rag-research (read-only)
        |                                             |
        v                                             v
  contained leaf spawned                        contained leaf spawned
        |                                             |
        v                                             v
  Drive door: fixed search, read each note      embeddings door: embed the question
        |                                             |
        v                                             v
  parse date header, chunk per paragraph        memory door: search, top 5 chunks
        |                                             |
        v                                             v
  per chunk: embeddings door, then              ONE chat call through the model door:
  memory door upsert (stable id)                  system  = fixed instruction only
        |                                         user    = passages + question
        v                                             |
  "indexed N chunks (M undated)"                      v
        |                                       answer (from the artifact store)
        v                                             |
  receipt: door calls, write line               receipt: provenance line, retrieval note
  (no provenance line: no chat call)            door calls, containment tier
```

Both halves share the `ask` machinery of steps 1 to 8 in
[`lifecycle-ask.md`](lifecycle-ask.md): invoker, installed snapshot, registry
gate, menu, classifier, confirmation gate, spawn, answer, receipt. Everything
below is what the leaf does between "spawned" and "answered".

## Indexing the notes (rag-ingest)

The run input is ignored; the agent does one fixed job.

1. **Find the notes.** It runs one fixed search against the `drive` tool
   resource (the query is `sync`). It expects one hit per line, a document id
   then a title. It never searches by your prompt, so a prompt cannot steer
   which documents are read.
2. **Read each note.** One read per hit, through the same door.
3. **Take the date.** The first line of a note is expected to read
   `Meeting notes - YYYY-MM-DD`. If it does not, or the date does not parse,
   the note is *undated*: it is still indexed, with an empty date, and counted.
4. **Chunk.** One chunk per paragraph (blank-line separated). A paragraph that
   is too long is packed on sentence boundaries, so a sentence is not cut in
   half; only a single sentence longer than the cap is split, at whitespace, as
   a last resort.
5. **Embed.** Each chunk goes through the embeddings door under the logical
   model name `embed`, which the operator maps to a real model.
6. **Write.** Each chunk is upserted into the `memory` tool resource, collection
   `notes`, with the stable id `<documentId>#<chunkIndex>` and the metadata
   `source`, `chunk_index`, and `date`. Because the id is stable, running the
   index again overwrites the same chunks instead of duplicating them.

The result is one line, `indexed N chunks (M undated)`, where N counts chunks
stored and M counts chunks (not notes) whose note had no parseable date.

A failure ends the run with a reason, and chunks already stored stay stored:
there is no rollback.

### Why `ask` confirms first

The memory store's upsert tool is a write, so the agent holds a **read-write**
tool grant. The confirmation gate in
[`lifecycle-ask.md`](lifecycle-ask.md#the-confirmation-gate) waves an agent
through only when it is `grounded` and holds no read-write grant; `rag-ingest`
fails both tests. On a terminal, `ask` asks `[y/N]` and tells you the run will
write to your store and that this cannot be undone. `--yes` runs it
non-interactively. With no terminal and no `--yes`, the pick is refused with a
message saying so, because consent is never assumed from a closed input.

### What the ledger records for an index run

The leaf's own run ledger records the door traffic, and the receipt reports it
per child as "attempted xN (succeeded xM)":

- the **tool doors**: the Drive search and reads, and the memory upserts;
- the **model door**: one `embeddings` call per chunk, shown separately from
  `chat` in the door summary (there is no chat call);
- the **write line**: the count of succeeded tool calls on a tool outside its
  resource's `read_only_tools`. Here that is the upserts. That a call happened
  and succeeded is the ledger's record; that it counts as a write is the
  operator's configuration.

`rag-ingest` is unstamped, makes no chat call, and so prints no provenance
line. It is a writer, not an answerer, and the receipt does not dress it up as
one.

## Retrieving and grounding (rag-retrieve and rag-research)

The two answering agents retrieve identically and differ only in what the model
is told.

1. **Embed the question.** The prompt text goes through the embeddings door as
   `embed`, the same logical model the notes were embedded with.
2. **Search the store.** One `memory_search` for the nearest five chunks in
   collection `notes`. Each hit carries its text, its source, and its date. The
   agents hold a read-only grant on the memory resource and have no Drive grant
   at all: they answer from what was indexed, and cannot read Drive, or write,
   even if asked to.
3. **Make one chat call** through the model door as `chat`, with a fixed shape:
   - the **system message** holds only a static instruction;
   - the **user message** holds the retrieved passages, each with its source and
     date, framed as quoted data to ignore any instructions inside, followed by
     the question.

Retrieved note text never goes in the system message. A note is data someone
wrote, possibly long after the fact and possibly not you; keeping it out of the
system role keeps it out of the position the model treats as the operator's own
instruction. The acceptance run asserts this directly: a sentence planted in a
note appears in a non-system message of the chat request and in no system
message.

### rag-retrieve: only from the notes

The instruction tells the model to use only the supplied passages, to cite
source and date, and to reply that the answer is not in the notes rather than
guess. If the search returns nothing at all, the agent does not call the model:
it answers "not in the notes" directly. That run therefore has no chat call and,
by the evidence rule below, no provenance line.

### rag-research: the notes and the model

The instruction lets the model use both the passages and its own knowledge,
asks it to say which parts come from the notes, and not to invent specifics
about your notes. It always makes the chat call, even when nothing matched (it
then tells the model no notes matched). It is the agent to ask when the answer
may legitimately go beyond your notes; `rag-retrieve` is the one for notes-only
answers.

## The honest receipt

After the answer, `ask` prints the receipt on stderr, built as described in
[`lifecycle-ask.md`](lifecycle-ask.md#the-answer-and-the-receipt). For a
retrieval run, three lines carry the weight.

**The provenance line is evidence-gated.** It appears only when the leaf's own
ledger holds a `chat` model call that succeeded or was streamed. The classifier's
calls are on another ledger and never count. So a run that retrieved and then
failed to reach the model, or `rag-retrieve` answering "not in the notes"
without a chat call, prints no provenance line at all.

**The wording is the operator's declaration.** It follows the stamped
`grounding`: for `rag-retrieve` the line reads "from your data"; for
`rag-research`, "your notes and the model". It is not computed from the answer.

**The retrieval note is a count from the ledger.** Beside the provenance line,
the receipt says "retrieval observed (read-tool call xK)" when the leaf's ledger
holds K succeeded read-only tool calls, and "no retrieval observed" otherwise.
A `grounded` or `mixed` declaration with no retrieval behind it is printed as
declared only, never as an unqualified "from your data". If the leaf ledger's
hash chain did not verify, the line is qualified "(leaf ledger integrity not
verified)".

### What this proves, and what it does not

It shows, from the run's own records, that a chat call succeeded and that a
read-only tool call succeeded. It does **not** show that the answer used what
the read returned, that the passages were relevant, or that the model did not
add facts of its own. Agenthof records that retrieval happened; it does not read
the answer and judge it. "Grounded" is an operator's declaration that the agent
is built to answer from your data, shown next to an observed fact, not a
measurement of any single answer.

The door counts say "attempted", never "sent". A call that failed or was refused
may have been stopped at the door or may have reached the provider or resource
first, and the ledger does not say which. A streamed model call is shown as
started, because the ledger does not record how a stream ended.

## Containment

Each agent is a **contained leaf**. The orchestrator spawns it through the spawn
gate, the supervisor creates its compartment, and the receipt reports the
containment tier the supervisor reported, as recorded in the ledger. On podman
the compartment has no host filesystem access by construction; on macOS Seatbelt
it is containment by configuration, as
[`lifecycle-ask.md`](lifecycle-ask.md#containment-of-the-installed-configuration)
states plainly.

Inside it, the agent has no network of its own to the model, the embeddings
provider, Drive, or the memory store. It reaches each only through the per-run
gateway, which admits a call only if the agent's grant names that model or tool,
and records it either way. That is Article I, **contained by construction**,
applied to retrieval: `rag-retrieve` cannot write because the gateway holds no
write grant for it, not because its instructions say it should not, and
`rag-ingest` cannot call a chat model because it was never granted one.

The ledger that records all of this is [Article III](constitution.md) evidence:
each record is hash-chained to the one before, so editing a record is caught by
the next record's link — except the final record, which has none, and a rewrite
that recomputes every later link to match; those, with truncating or appending
to the ledger, are caught only against a head kept off the machine. It is
limited evidence, not
tamper-proof against someone who controls the ledger. It carries digests,
statuses, and bounded previews; the answer body is read from the artifact store
by digest and never rides a ledger.

## Limits, stated plainly

- **A crafted note can try to steer the answer.** The passages are placed in the
  user message and framed as quoted data, but a stored note is untrusted text
  and the model may still be influenced by it. Containment bounds the blast
  radius, since the agent can only reach the doors it was granted and a
  read-only agent cannot write, but it does not sanitize the note. Anyone who can
  put a note where `rag-ingest` will read it can try this.
- **Stale chunks stay.** There is no delete. If a note shrinks or is removed,
  re-indexing overwrites the chunk ids that still exist and leaves the others,
  which can still surface in retrieval. Re-running is idempotent, not a sync.
- **The receipt counts attempts, not what physically left.** Note text reaches
  the embeddings provider on the way in and the chat provider on the way out
  (the retrieved passages are part of the chat request), and it enters the
  ledger as a bounded result preview. The receipt reports calls attempted and
  succeeded; it does not claim to know what bytes crossed which boundary.
- **An empty or missing collection returns zero hits, as a success.** Searching
  a collection that was never indexed is not an error. `rag-retrieve` then says
  the answer is not in the notes; `rag-research` answers from the model alone.
  Neither is a sign that indexing worked, or that your notes lack the answer.
- **The date is stored, not used.** Each chunk keeps its meeting date, and the
  passages show it as a citation, but retrieval does not filter or rank by it.
- **Retrieval is as good as the embedding.** The top five chunks by similarity
  are what the model sees. A relevant passage ranked sixth is not seen.
- **Grounding is a declaration, not a measurement.** See above: the receipt
  shows that a read happened, not that the answer used it.

## What ships today, and what is reserved

Shipped today, and the only guarantees on this page:

- `rag-ingest`: a fixed Drive search, per-note date header, per-paragraph
  chunks, embeddings through the model door, upserts to the memory store under
  stable ids.
- `rag-retrieve` and `rag-research`: embed, top-five search, one chat call with
  the passages in the user message.
- The receipt's evidence-gated provenance line, the `grounded` and `mixed`
  wording, the retrieval note, and the attempted and succeeded door counts.
- Confirm-on-write: a run with a read-write grant asks before it runs, and
  `--yes` bypasses the question.

Reserved for later, not a guarantee: narrowing retrieval by the stored date
(for example "what did we decide last month"), which today the stored date does
not do.

## See also

- [`lifecycle-ask.md`](lifecycle-ask.md) - the orchestrator these agents run under: routing, the confirmation gate, and the receipt.
- [`lifecycle-spawn.md`](lifecycle-spawn.md) - how each agent is started, confined, and recorded as a child run.
- [`lifecycle-enroll.md`](lifecycle-enroll.md) - how the agents were installed from signed cards.
- [`lifecycle-model.md`](lifecycle-model.md) - the model door: the chat and embeddings calls.
- [`lifecycle-tool.md`](lifecycle-tool.md) - the tool door: the Drive and memory calls.
- [`constitution.md`](constitution.md) - Article I (contained by construction), Article III (the ledger is limited evidence).
- [`reference/config.md`](reference/config.md) - [`grounding`](reference/config.md#grounding), [`may_spawn`](reference/config.md#may_spawn).
