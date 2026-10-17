# 0007: Integration vendors may be named in public code

**Status:** accepted · **Date:** 2026-10-17

## Context
ADR 0002 keeps private identifiers out of this repository with a scrub gate.
At first the private denylist also blocked the names of every product in the
stack. Real integrations need those names: an API host to call, a header that
carries identity. Hiding them would mean pushing URLs and header names into
private configuration, which makes the code harder to read and reuse, and the
stack would still be inferable from the code's shape.

## Decision
Products this project integrates with may be named in code and docs: the
EDR/SIEM platform (LimaCharlie), the mesh VPN (Tailscale) and the edge tunnel
(Cloudflare). The private denylist keeps blocking:
- people, the firm, hostnames, addresses, tenant/org/sensor ids
- the managed MDR partner and other vendor relationships that reveal business arrangements
- infrastructure that isn't an integration (hypervisor, storage, secrets manager, notes tool)
- AI product and model names, until the disclosure stance is decided

## Consequences
- Integration code is concrete and reusable by others running the same stack.
- Anyone reading the repo learns which products it supports. That's the point
  of a public integration, and none of it identifies a specific environment.
