# Database: schema, roles, migrations

Postgres 16, schema managed by Alembic (`api/src/soc_api/migrations`). Isolation design:
[ADR 0001](../adr/0001-postgres-from-day-one.md).

## Roles

| Role | Used by | Can do |
|---|---|---|
| owner (deploy-defined) | migrations only | Creates and owns the tables. Needs `CREATEROLE` and must own the database; it does **not** need to be, and should not be, a superuser. Never used by a service. |
| `soc_app` | console, workers | Read and write rows of **one client**: the one in the session setting `app.client_id`. With it unset it sees nothing. No `DELETE`; `case_event` is append-only. |
| `soc_ingest` | the public ingest handler | **No table privileges.** It can only call `ingest_alert()`, which maps a delivery to a source, attributes it (unknown tenant -> the Unassigned client) and inserts idempotently on `(source, event_id)`. |
| `soc_ingest_writer` | nobody (never logs in) | Owns `ingest_alert()`, so the function runs with only `SELECT` on `source` and `INSERT` on `alert`. An RLS policy allows an alert only for its source's client or Unassigned. |

All three service roles are created `NOLOGIN` and are never superuser, `BYPASSRLS`,
`CREATEROLE` or `CREATEDB`. Roles are cluster-wide, so they can already exist: if one has
any of those (or `soc_ingest_writer` can log in), the migration stops instead of reusing it. Deploy gives each a login and a password
from the secrets manager; no credential is in this repo.

The owner bypasses RLS (policies are not forced on it), so the app must never connect
as the owner. A session that can run `SET app.client_id` can pick its client; the
application is what sets it, and `soc_ingest` has no way to read the setting's effect.

## On the host (Stage A)

PostgreSQL 16 runs as the `db` service in `deploy/compose.yml` (profile `db`, turned
on by `deploy.sh` when the secret files exist). It lives on an **internal** compose
network that only `api`, `db` and the one-off `migrate` job join. The tunnel is not
on it, nothing is published on the host, and the console does not use the database
yet. The data directory is `/srv/soc/pgdata` (uid 999, mode 700).

| File (mode 600) | Holds | Read by |
|---|---|---|
| `env/db.env` | `POSTGRES_PASSWORD` (superuser, used once at first start) and `SOC_DB_OWNER_PASSWORD` | `db` |
| `env/db-owner.env` | `SOC_MIGRATE_URL` (the `soc_owner` URL, host `db`) and `SOC_INGEST_DB_PASSWORD` | `migrate` |
| `env/ingest.env` | the webhook secrets and the `soc_ingest` URL (same password) | `api` |

First start (an empty `pgdata`) runs `deploy/db/initdb/`: it creates `soc_owner` (can
log in, `CREATEROLE`, not a superuser) and the database `soc`, then rewrites
`pg_hba.conf` so the **`postgres` superuser is refused over the network**. It still
works on the container's own socket, which needs root on the host:

    # On CT 110 as root: a shell as the superuser (for example to reset a lost password)
    /opt/soc-platform/deploy/soc-compose.sh exec db psql -U postgres -d soc

`deploy/soc-compose.sh` runs compose exactly as `deploy.sh` does (project, both
compose files, the pinned image, the `db` profile). Use it for every one-off command
on the host; a bare `docker compose -f compose.yml` would look for an image and
project that do not exist there.

The init scripts run only when `pgdata` is empty. Changing `SOC_DB_OWNER_PASSWORD` in
`db.env` later does nothing by itself: in the superuser shell above run
`\password soc_owner` (psql hashes the new password before sending it, so it never
reaches the server or its log), then put the same value in `db-owner.env`.

### What a deploy does
`deploy.sh` starts `db`, waits for its health check (over TCP, so the temporary
first-start server does not count), then runs the migration job as `soc_owner`:
`python -m soc_api.db deploy` = `upgrade` then `logins`. `logins` gives `soc_ingest`
its login, a 10-connection cap and the password in `SOC_INGEST_DB_PASSWORD`. The
password is turned into a SCRAM-SHA-256 verifier in the job, so the server and its
log never see the plain value. It changes nothing else about the role. To rotate:
change the password in `db-owner.env` and `ingest.env`, then deploy. Between the
migration job and the swap the running app cannot open new database connections,
so expect a few seconds of 503s (the sender retries, if it does; see the retry test).

**Expand, then contract.** A rollback swaps the image only; it never runs a
downgrade. So every migration must keep working with the previous release's code:
add columns and tables first, remove or rename in a later release once nothing old
runs. A migration that breaks the previous image breaks the rollback.

If the job fails, the deploy stops with the previous image restored and the
services untouched. Each Alembic migration is one transaction, so a failed one
leaves the schema as it was.

## Run the migrations by hand

Where: the CT 110 host or a dev shell, as the owner role.

    SOC_MIGRATE_URL=postgresql+psycopg://owner@host/soc python -m soc_api.db upgrade

`python -m soc_api.db downgrade` steps back one revision (drops tables; roles remain).

## Seed a tenant

    # On CT 110 as root, with the seed file in /srv/soc/seed/, after a deploy:
    /opt/soc-platform/deploy/soc-compose.sh run --rm --entrypoint python \
      migrate -m soc_api.seed /seed/<file>.json

Safe to repeat: rows that already match are left alone. A row that exists with
different values (for example a source that would move to another client) stops the
run with an error and changes nothing. The file may list several `sources`.

## Tests

The schema tests need a throwaway Postgres: set `SOC_TEST_DATABASE_URL` to a server
and a role that can create databases and roles. Without it they skip locally. CI sets
`SOC_REQUIRE_DB=1` so a missing database fails the job.

## Demo tenant

`fixtures/acme-demo/seed.json` is synthetic. `soc_api.seed.seed(url, path)` loads it.
Real client rows come from the private deploy repo.

## Stack check

`scripts/test-db-stack.sh <image>` (run by CI) brings up the real `db`, `migrate` and
`api` services with throwaway secrets and checks a signed delivery is stored once, a
repeat adds nothing, a bad signature stores nothing, the tunnel's network cannot
resolve or reach `db`, the superuser is refused over the network, `soc_ingest` can
read nothing, and a stopped database gives a 503 while `/healthz` stays up.
