# Architecture decision records

One file per decision: context, the decision, and its consequences. A
superseded record stays in place and links to the one that replaces it.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-postgres-from-day-one.md) | PostgreSQL from the first table, with row-level security per client | accepted |
| [0002](0002-public-code-private-deploy.md) | Public-ready code repo, private deploy repo | accepted |
| [0003](0003-stack.md) | FastAPI, Postgres-backed job queue, React console | accepted |
| [0004](0004-edr-platform-is-the-telemetry-store.md) | The EDR/SIEM platform stores raw telemetry; this project stores alerts and cases | accepted |
| [0005](0005-supply-chain-controls.md) | Pinned actions, signed images, SBOMs, verify before deploy | accepted |
| [0006](0006-security-features-while-private.md) | Compensating controls while the repo was private; outcome of going public | completed |
| [0007](0007-integration-vendor-names.md) | Integration vendors may be named in public code; identifiers stay private | accepted |
| [0008](0008-own-case-store-link-platform-cases.md) | Own case store is the system of record; incidents link a platform case for investigation | accepted |
