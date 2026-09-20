# Security Policy

Agenthof is a governance/containment platform, so security reports get
priority over everything else.

## Reporting

Email security@agenthof.dev with subject `[agenthof security]`, or use GitHub's
private vulnerability reporting on this repository. Please do not open public
issues for exploitable problems. You'll get an acknowledgement within 72
hours.

## Scope of interest

Jail escapes (path confinement, symlinks, dotfiles), ledger integrity bypass
(hash-chain forgery, event suppression, beyond the limits documented in
docs/concepts.md), identity spoofing (invoker method or subject), secret
leakage into ledger/logs/errors, and adapter-boundary abuse (SSRF, resource
exhaustion).

## Supported versions

Pre-1.0: only the latest release / main is supported.
