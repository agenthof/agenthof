# Standards & prior art

Agenthof's design is not invented from scratch. Its guarantees rest on
well-established security and governance principles, and on published standards
and frameworks for access control, identity, audit, and AI risk. This page maps
the ideas Agenthof builds on to the documents that define them, so you can check
the design against the source rather than taking our word for it.

**How to read this.** Two honest framings, and only these:

- **Inspiration** — principles Agenthof deliberately builds toward.
- **Alignment** — where Agenthof's behavior *maps to* what a standard describes.

We say "aligns with" or "inspired by," **never** "certified" or "compliant."
Agenthof is not audited or certified against any of these; alignment is a design
claim you can verify from the code and the [constitution](constitution.md), not a
third-party attestation. Where Agenthof deliberately diverges from a standard, we
say so ([below](#where-agenthof-deliberately-diverges)).

## Least privilege & secure-by-design

| Reference | What it is | How Agenthof aligns |
| --- | --- | --- |
| [Saltzer & Schroeder, *The Protection of Information in Computer Systems* (1975)](https://web.mit.edu/Saltzer/www/publications/protection/) | The paper that named **least privilege** and **fail-safe defaults**. | The whole posture: default-deny authorization, no privilege by omission, capability only through governed doors (Articles I, VI). |
| [Hardy, *The Confused Deputy* (1988)](http://cap-lore.com/CapTheory/ConfusedDeputy.html) | Why a proxy that forwards a caller's authority is dangerous. | The gateways mint their own credential and **never pass the agent's token upstream** (Article I, no-passthrough). |
| [NIST SP 800-207, *Zero Trust Architecture*](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf) | The US government reference for "never trust, always verify," per request. | Every action is authorized at a governed door with a per-run identity; nothing is trusted by network position (Articles I, II). |

## Access control & audit

| Reference | What it is | How Agenthof aligns |
| --- | --- | --- |
| [NIST SP 800-53 Rev. 5](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf) | The canonical security-control catalog; its **AC** (access control) and **AU** (audit) families. | RBAC and the hash-chained audit ledger are the AC/AU floors — free forever in the core (Article IV). |
| [NIST RBAC model (Sandhu, Ferraiolo, Kuhn, 2000)](https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=916402) | The reference role-based access-control model. | Agenthof implements **flat RBAC** (roles gate access by group); it does not implement role hierarchies or constraints. |

## Identity & delegation

| Reference | What it is | How Agenthof aligns |
| --- | --- | --- |
| [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) · [OAuth 2.0 (RFC 6749)](https://www.rfc-editor.org/rfc/rfc6749) | The mature standards for human login (OIDC) and machine-to-machine grants (client-credentials, §4.4). | The load-bearing pair: OIDC establishes the invoker; client-credentials mints upstream tokens. Only mature, widely-supported standards are required. |
| [RFC 9728, *Protected Resource Metadata*](https://www.rfc-editor.org/rfc/rfc9728) | How an OAuth resource server advertises how to authenticate to it. | The gateway acts as a resource server and validates audience; foreign tokens are rejected. |
| [RFC 8693, *Token Exchange*](https://www.rfc-editor.org/rfc/rfc8693) · [SPIFFE](https://spiffe.io/) | Emerging standards for delegated and workload identity. | **Optional federation upgrades**, not prerequisites, never load-bearing for a release (Article II). Token exchange ships as one such upgrade, chosen per tool resource: a resource declared `grant_type: token_exchange` is called on behalf of the invoking human, by impersonation (no actor token) — see [`lifecycle-tool.md`](lifecycle-tool.md#on-behalf-of-the-invoker). SPIFFE remains a reserved seam in the auth-federation broker. |

## Hash-chained ledger & tamper-evidence

| Reference | What it is | How Agenthof aligns |
| --- | --- | --- |
| [Schneier & Kelsey, *Secure Audit Logs* (1999)](https://www.schneier.com/wp-content/uploads/2016/02/paper-auditlogs.pdf) · [Crosby & Wallach, *Tamper-Evident Logging* (2009)](https://www.usenix.org/legacy/events/sec09/tech/full_papers/crosby.pdf) | The foundational work on append-only, hash-linked audit logs. | The ledger is exactly this: each event carries the SHA-256 of its predecessor; `audit` verifies the chain (Article III). |
| [RFC 9162, *Certificate Transparency*](https://www.rfc-editor.org/rfc/rfc9162) | The Merkle-tree transparency-log model for proving a log to a third party. | The model for a **reserved** external-anchoring tier — publishing the chain head off-machine so tampering is provable to others, not just detectable locally. Not shipped today. |

## Tool / MCP & gateway security

| Reference | What it is | How Agenthof aligns |
| --- | --- | --- |
| [MCP Authorization spec (2026-07-28)](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) | The Model Context Protocol's rule that a server must not accept or transit tokens meant for others. | The tool/MCP door mints a per-call resource credential and never forwards the agent's run token — directly the spec's mandate. One stated deviation from the letter: the reference bridge for stdio servers (`deploy/refbridge`) passes Agenthof's own resource credential on to the server it fronts, over a private Unix socket, so that server can use it. That token is never a caller's, is never treated as the caller's identity, and the ledger records the injection, so the confused-deputy and audience hazards the rule exists for do not arise; see [`lifecycle-tool.md`](lifecycle-tool.md#a-stdio-server-behind-a-bridge). |
| [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) | Guidance on token passthrough, the confused-deputy problem, and local (stdio) servers. | The tool door is built around exactly these hazards; per-tool allowlisting and least privilege bound what an agent may call. |

## AI governance & agent threats

| Reference | What it is | How Agenthof aligns |
| --- | --- | --- |
| [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) · [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/) | The community threat lists for agentic and LLM systems. | Agenthof is a mitigation layer for several entries — excessive agency, insecure tool use, and identity/authorization gaps in particular. |
| [NIST AI RMF (AI 100-1)](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf) · [Generative AI Profile (AI 600-1)](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf) | The US framework for managing AI risk, plus its generative-AI profile. | The free framework Agenthof's governance and audit map onto; also the free crosswalk for the paywalled ISO/IEC 42001. |
| [MITRE ATLAS](https://atlas.mitre.org/) | The adversarial-threat knowledge base for AI systems. | A reference for the threats the governed doors and audit trail are meant to make investigable. |
| [EU AI Act (Reg. 2024/1689)](https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng) | The EU's AI regulation, incl. record-keeping and log-retention duties (Art. 12, 19, 26). | The ledger plus `runs prune` retention give the self-hosting controller the record-keeping substrate those articles require. |
| [ISO/IEC 42001](https://www.iso.org/standard/42001) | The AI-management-system standard (**paywalled**). | Conceptually aligned; use the free NIST AI RMF above as the practical crosswalk. |

## Where Agenthof deliberately diverges

Alignment is honest about its limits. Agenthof departs from a naive reading of
some of the above **on purpose**:

- **Tamper-evident, not tamper-proof.** The hash chain makes tampering
  *detectable* against an off-machine head; it does not make it *impossible*. No
  Agenthof document calls the ledger tamper-proof (Article III).
- **Containment is the operator's sandbox's job.** Agenthof governs and records;
  it does not itself confine an agent's process or network. That boundary is
  explicit (Article I), with a reference sandbox provided separately.
- **Flat RBAC.** Roles gate by group; there are no role hierarchies or
  constraints from the full NIST RBAC model.
- **Mature standards only are load-bearing.** OIDC and OAuth client-credentials
  are required; token exchange, SPIFFE, and similar are optional upgrades, never
  release prerequisites (Article II).

---

These references are cited as prior art and inspiration. Listing them does not
imply endorsement of Agenthof by NIST, IETF, OWASP, MITRE, ISO, the EU, or any
other body.
