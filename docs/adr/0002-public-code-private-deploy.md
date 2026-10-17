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
printed.

## Consequences
- Going public is flipping a switch, not rewriting history.
- Commits use a noreply author address.
- Anything real goes through config, which is better design anyway.
