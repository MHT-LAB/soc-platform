# 0002: Public-ready code repo, private deploy repo

**Status:** accepted · **Date:** 2026-10-17

## Context
The project is documented in public. Earlier experience showed that exporting
private notes after the fact leaks details: paths, hostnames and process notes
slipped into a public repo and stayed there for weeks. A security project's
public write-ups are reconnaissance material for anyone profiling its author.

## Decision
Split the project in two:
- **This repo** holds code, generic detection rules, synthetic fixtures and
  design docs. It contains no real identifiers *by construction*: everything
  environment-specific is configuration supplied at deploy time.
- **A private deploy repo** holds environment files (pointing at a secrets
  manager, never secret values), real client and endpoint seed rows, rule
  overrides, and the scrub denylist.

A scrub gate (`scripts/scrub-check.sh`) runs in pre-commit and CI. It checks
generic patterns (private addresses, home paths, stray emails, commit author
addresses) plus a private denylist that is passed in as a CI secret and never
printed. It scans the tracked files, every line added by every commit in the
pull request (so a name added and removed within one PR is still caught, since
it would stay public in the PR ref), the commit messages, and the PR title and
body (a squash merge turns them into the commit message on `main`). On a pull
request it also checks the author and committer names in the range, because a
squash adds every other author as a `Co-authored-by` line on `main`. A
Dependabot PR's body is generated release notes, so it only warns: such a PR
is merged with an explicit one-line message, and its branch is never updated
with GitHub's "update branch" (ask Dependabot to rebase or recreate it).

The gate fails closed. In CI a missing or empty denylist fails the check; the
only exception is a Dependabot PR that changes dependency files alone. Anything
the gate cannot run is a failure, not a pass. In CI it never prints the matched
text, because public CI logs outlive a force-push. `scripts/test-scrub-check.sh`
tests the gate itself against planted leaks and runs in CI (`make test-scrub`).

## Consequences
- Going public is flipping a switch, not rewriting history.
- Commits use a noreply author address.
- Anything real goes through config, which is better design anyway.
