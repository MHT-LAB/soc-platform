# Database: schema, roles, migrations

Postgres 16, schema managed by Alembic (`api/src/soc_api/migrations`). Isolation design:
[ADR 0001](../adr/0001-postgres-from-day-one.md).

## Roles

| Role | Used by | Can do |
|---|---|---|
| owner (deploy-defined) | migrations only | Creates and owns the tables and `ingest_alert()`. Never used by a service. |
| `soc_app` | console, workers | Read and write rows of **one client**: the one in the session setting `app.client_id`. With it unset it sees nothing. No `DELETE`; `case_event` is append-only. |
| `soc_ingest` | the public ingest handler | **No table privileges.** It can only call `ingest_alert()`, which maps a delivery to a source, attributes it (unknown tenant -> the Unassigned client) and inserts idempotently on `(source, event_id)`. |

`soc_app` and `soc_ingest` are created `NOLOGIN` and are never superuser or `BYPASSRLS`
(the migration re-asserts that on every run). Deploy gives each a login and a password
from the secrets manager; no credential is in this repo.

The owner bypasses RLS (policies are not forced on it), so the app must never connect
as the owner. A session that can run `SET app.client_id` can pick its client; the
application is what sets it, and `soc_ingest` has no way to read the setting's effect.

## Run the migrations

Where: the CT 110 host or a dev shell, as the owner role.

    SOC_MIGRATE_URL=postgresql+psycopg://owner@host/soc python -m soc_api.db upgrade

`python -m soc_api.db downgrade` steps back one revision (drops tables; roles remain).

## Tests

The schema tests need a throwaway Postgres: set `SOC_TEST_DATABASE_URL` to a server
and a role that can create databases and roles. Without it they skip locally. CI sets
`SOC_REQUIRE_DB=1` so a missing database fails the job.

## Demo tenant

`fixtures/acme-demo/seed.json` is synthetic. `soc_api.seed.seed_demo(url, path)` loads it.
Real client rows come from the private deploy repo.
