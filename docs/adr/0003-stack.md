# 0003: Stack

**Status:** accepted · **Date:** 2026-10-17

## Decision
| Layer | Choice | Why |
|---|---|---|
| API and workers | Python 3.12, FastAPI, SQLAlchemy, Alembic | The EDR platform SDK and the LLM agent SDK are both Python; FastAPI gives typed request validation and async I/O for webhooks and streaming |
| Database and queue | PostgreSQL 16 | See ADR 0001 |
| Console | React, TypeScript, Vite, Apache ECharts | Rich, dense visuals (flows, heatmaps, timelines) with type safety |
| Live updates | Server-sent events | One-way stream is all the console needs; simpler than WebSockets |
| Packaging | uv with a hashed lockfile | Reproducible installs; hashes defeat tampered packages |
| Runtime | Docker Compose | Same file in dev and prod; portable to a VPS |

## Consequences
Plain, well-commented patterns are preferred over clever ones. The project is
also a learning vehicle and will be maintained by one person at first.
