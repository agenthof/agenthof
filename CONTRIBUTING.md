# Contributing to Agenthof

Thanks for your interest. Agenthof is early — issues and discussion are as
valuable as code.

## Developer Certificate of Origin (DCO)

We use the [DCO](https://developercertificate.org/) instead of a CLA. Every
commit must be signed off, certifying you have the right to submit the code
under the project's Apache-2.0 license:

    git commit -s -m "feat: your change"

which adds a `Signed-off-by: Your Name <you@example.com>` trailer. PRs with
unsigned commits will be asked to amend. Because contributions are accepted
under Apache-2.0 via DCO (not assigned via CLA), no single party can
relicense your contribution out from under you.

## Development

- Go version: see `go.mod`. Build/test: `go build ./... && go test ./...`.
- Run the CLI journeys: `go test ./cmd/agenthof -run TestScript`.
- Format with `gofmt`; CI enforces it, plus `go vet`, golangci-lint,
  govulncheck, gitleaks, and a FIPS build gate (`GOFIPS140=latest`).
- The constitution (`docs/constitution.md`) is binding: additive-only ledger
  schema, commands only on the config allowlist (attested; Agenthof does not
  run them), no secrets in config or logs.
- Every feature, and every new event type, must trace to a specific
  constitution article or to a concept documented in `docs/concepts.md`. If
  it can't be traced, it doesn't ship.
- Changes land as small, independently testable units, test first. Every
  commit must be green on `gofmt`, `go build`, `go vet`, and `go test`.

## Engineering guidelines

What we optimise for, and what to do when these pull against each other.

**Correctness first.** A change is done when its *failure* modes are tested, not
when the happy path works. Tests exercise real behavior rather than mocks of our
own code. Where a design can either fail clearly or recover silently, fail
clearly: a loud error an operator can act on beats a guess that corrupts a
ledger. For anything that records or enforces governance, the test that proves
the guarantee holds is part of the feature.

**Easy to reason about.** A reader should be able to hold a file in their head
and answer: what does this do, how do I use it, what does it depend on. One
responsibility per file; split when a file starts answering two questions. Name
things after what they are. Cross-package behavior should be legible from the
interfaces without reading implementations.

**Keep it simple.** Build the simplest thing that satisfies the constitution and
the tests. No abstraction before its second real caller, no configuration knob
before someone needs it, no capacity planning for scale we do not have. Deleting
a possibility is usually better than adding a flag to control it.

**Idiomatic Go.** Follow the standard library's shape. Wrap errors with `%w` and
let callers decide; return errors rather than logging and continuing; keep zero
values useful. Avoid reflection and cleverness in anything on a correctness
path. `gofmt`, `go vet`, and golangci-lint are gates, not suggestions.

**Secure by construction.** Prefer designs where the bad outcome is impossible
over designs where it is merely forbidden — a jailed path beats a path check.
Validate at the boundary, once, and trust the validated value inward. Never log
or persist secrets, tokens, or raw credentials. Bound anything an outside party
controls: response sizes, string lengths written to the ledger, retries.

When these conflict, correctness wins, then clarity. An optimisation that makes
the ledger harder to verify, or a clever abstraction that makes a security
property harder to see, is not a good trade.

## Commit style

One-line imperative subject, `type(scope): summary` (e.g.
`feat(engine): ...`, `fix: ...`, `docs: ...`, `ci: ...`, `test: ...`).
