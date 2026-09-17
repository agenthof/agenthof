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
  schema, no exec in agent runtimes, no secrets in config or logs.

## Commit style

One-line imperative subject, `type(scope): summary` (e.g.
`feat(engine): ...`, `fix: ...`, `docs: ...`, `ci: ...`, `test: ...`).
