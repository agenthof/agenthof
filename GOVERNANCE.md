# Governance

Agenthof is designed so that trust rests on **verifiable properties of the
project**, not on who maintains it. This document says who is accountable, how
the project changes, and why you do not have to take anyone's word for it.

## Who maintains Agenthof

Agenthof is maintained by **rojaneerdev**. It is independent — not owned by,
funded by, or steering toward any vendor's product. The project's credibility
comes from the guarantees below, all of which you can check for yourself.

## What is guaranteed, and how it is enforced

These are binding, not aspirational:

- **Apache-2.0, forever.** The core license will not change to a BUSL-style or
  source-available license, and no clause will restrict who may run, fork, or
  compete with the software. This is written into the constitution
  ([`docs/constitution.md`](docs/constitution.md), Article V).
- **A binding constitution.** Every change must honor the invariants in
  [`docs/constitution.md`](docs/constitution.md) — containment, identity, the
  hash-chained ledger, compliance floors, the license, and scope discipline.
  Those invariants change only by an explicit commit that amends that file and
  states which article changed and why. No code change, config default, or
  other document amends them silently.
- **Compliance floors free in core.** Audit logging, basic RBAC, and retention
  controls ship in the open-source core and will not become paid features
  (Article IV).
- **Honest claims.** The docs state what the system does *not* do as plainly as
  what it does — for example, the ledger is append-only and tamper-evident, not
  tamper-proof, and its limits are documented rather than glossed over. No
  document may overstate a guarantee.
- **Built on established standards.** The design aligns with recognized security
  and AI-governance standards — NIST (SP 800-207, 800-53, AI RMF), OWASP, OAuth /
  OpenID Connect, the MCP authorization spec, and the EU AI Act. The full mapping,
  including where Agenthof deliberately diverges, is public in
  [`docs/standards.md`](docs/standards.md). This is honest alignment you can verify
  from the design and the constitution — not third-party certification.
- **Provenance of contributions.** Contributions are made under the Developer
  Certificate of Origin (see [CONTRIBUTING.md](CONTRIBUTING.md)); every commit
  is signed off.

None of these depend on taking anyone's word for it — they are enforced by the
license, the constitution, and the commit history, all public.

## How the project changes

- **Config is law.** Behavior traces to validated configuration, not hidden
  code paths; schema changes are additive — existing fields keep their meaning.
- **Amendments are explicit.** Constitutional changes are their own commits,
  naming the article and the reason.
- **Direction, not promises.** [`ROADMAP.md`](ROADMAP.md) shows where the
  project is heading, grouped by horizon. **Only the "Now" items are
  guarantees**; everything else is intent that will change as the project and
  its users learn.

## Security

Report vulnerabilities via [SECURITY.md](SECURITY.md) (security@agenthof.dev).

## "Who's behind this?"

Maintained by **rojaneerdev**, independently, under Apache-2.0 forever. Trust is
anchored in the license, the constitution, and the DCO — all public and
checkable. Contributions and scrutiny are welcome.
