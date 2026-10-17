# 0006: Compensating controls while private

**Status:** completed 2026-10-17 (repository is public) · **Date:** 2026-10-17

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

## Outcome (2026-10-17)
Made public after a pre-flight review of everything that becomes visible with
the code, not only the files:
- **History:** all commits and messages scanned against the private denylist
  and generic patterns: clean; authors are noreply only.
- **Pull requests and comments:** clean.
- **CI run logs:** six early runs contained the account's primary email,
  printed from the push event payload before email privacy was enabled.
  Those runs' logs were deleted; the runs and their results remain.
- **Actions:** only GitHub-owned actions and the ten third-party actions this
  repo uses may run; fork pull requests need approval before workflows run;
  the default token is read-only.
- **Container image:** remains private.

Enabled on the public repo: CodeQL (extended queries), secret scanning with
push protection, validity checks and generic patterns, Dependabot alerts and
security updates, private vulnerability reporting, and a `main` ruleset
(pull request required, squash only, all seven checks required, signed
commits, linear history, no force-push or deletion, no bypass).
