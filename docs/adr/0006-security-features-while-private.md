# 0006: Compensating controls while private

**Status:** accepted · **Date:** 2026-10-17

## Context
The repository starts private and becomes public after a scrub review at the
end of Sprint 0. On a free plan, branch protection, CodeQL code scanning and
secret push protection only apply to public repositories.

## Decision
While private:
- Pre-commit hooks run gitleaks, ruff, hadolint and the scrub gate locally.
- CI runs gitleaks, Semgrep, pip-audit, hadolint, Checkov, Trivy and the scrub
  gate on every push and pull request.
- All work still goes through pull requests by convention.

When public: enable CodeQL, secret scanning with push protection, private
vulnerability reporting, and a branch ruleset on `main` requiring pull
requests, passing checks and signed commits.

## Consequences
For a short window, merge rules are discipline rather than enforcement. CI
still reports every failure.
