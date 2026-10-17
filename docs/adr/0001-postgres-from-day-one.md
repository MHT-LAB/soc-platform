# 0001: PostgreSQL from day one

**Status:** accepted · **Date:** 2026-10-17

## Context
The first design started on SQLite for the first tenant and planned a move to
Postgres when a second client arrived. The system will run several workers at
once (ingest, outbox, reconcile, triage), stream live updates to the console,
add technicians with their own logins, and move to a VPS later.

## Decision
Use PostgreSQL 16 from the first migration. Every client-owned table carries
`client_id`, and **row-level security** policies restrict each database session
to one client. Migrations are managed with Alembic from the start. Background
jobs use the same database as a queue (`SELECT … FOR UPDATE SKIP LOCKED`), so
no separate broker is needed.

## Consequences
- Tenant isolation is enforced by the database, not only by application code.
  A bug in a query can't return another client's rows.
- One more container to run and back up (`pg_dump`, restore drill in Sprint 2).
- No later SQLite-to-Postgres migration.
