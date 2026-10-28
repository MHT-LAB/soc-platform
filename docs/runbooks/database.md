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
| `soc_worker` | the pager worker (migration `0002`) | **No table privileges.** It can only call six functions: `assign_cases`, `claim_pages`, `finish_page`, `heartbeat_counts`, `worker_state_get`, `worker_state_set`. Cross-tenant by design, which is why it is not `soc_app`. It never reads a raw payload. |
| `soc_console` | the console's case pages (migration `0004`) | **No table privileges.** It can only call four functions: `list_cases` (the queue), `get_case` (one case, its alerts with the raw payload as **text**, cut at 20000 characters, and its events), `ack_case` and `close_case` (a note is required). Staff view across clients; per-client roles come with sign-in. |
| `soc_console_writer` | nobody (never logs in) | Owns those four functions. Table access: `SELECT` on `client`, `alert`, `soc_case`, `case_event`, `notification`; `UPDATE (status, closed_at, closing_note)` on `soc_case`; `INSERT` on `case_event`; `UPDATE (acked_at)` on `notification`; each behind an RLS policy for this role. |
| `soc_worker_writer` | nobody (never logs in) | Owns those functions. Table access: `SELECT` on `client` and `alert`, `UPDATE (case_id)` on `alert`, `SELECT`/`INSERT` on `soc_case`, `INSERT` on `case_event`, `SELECT`/`INSERT`/`UPDATE` on `notification` and `worker_state`, each behind an RLS policy for this role. No `DELETE`. |

All seven service roles are created `NOLOGIN` and are never superuser, `BYPASSRLS`,
`CREATEROLE` or `CREATEDB`. Roles are cluster-wide, so they can already exist: if one has
any of those (or a `*_writer` role can log in), the migration stops instead of reusing it. Deploy gives each a login and a password
from the secrets manager; no credential is in this repo.

The owner bypasses RLS (policies are not forced on it), so the app must never connect
as the owner. A session that can run `SET app.client_id` can pick its client; the
application is what sets it, and `soc_ingest` has no way to read the setting's effect.

## First-time setup on the host

Run on CT 110 as root. Nothing here needs a person or a model to see a secret.

    # 1. A source name: lc- plus 16 random lowercase letters or digits. It is not a
    #    credential; it keeps strangers from finding the endpoint.
    SLUG="lc-$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"; echo "$SLUG"

    # 2. Generate every secret and write the three env files, pgdata and seed/.
    #    Prints once: the EDR webhook destination and key, and a NAME=value block.
    /opt/soc-platform/deploy/init-secrets.sh "$SLUG" <public-host>

    # 3. Save the block in the secrets manager (folder /soc, bulk import as .env),
    #    set the EDR output from the printed destination and key, then clear the
    #    terminal and its scrollback. Do not paste the output anywhere else.

    # 4. Put the tenant seed in /srv/soc/seed/ (private deploy repo), then deploy:
    cd /opt/soc-platform && git pull -q --ff-only && deploy/deploy.sh edge
    deploy/soc-compose.sh run --rm --entrypoint python migrate -m soc_api.seed /seed/<file>.json

    # 5. Prove the path end to end (a synthetic detection; it lands in Unassigned):
    deploy/soc-compose.sh exec -T api python -m soc_api.selftest --repeat
    deploy/soc-compose.sh exec -T api python -m soc_api.selftest --url https://<public-host>

`init-secrets.sh` never overwrites: if any target file exists it stops before creating
anything. The self-test prints only the HTTP status and a detection id. `200` twice
with the same id means the repeat was accepted and stored once; `503` means the
database is not reachable (nothing is stored); `401` means the key in the env file and
the key in the output differ. Its rows have rule `soc-selftest`, and the pager must
skip them.

### Rebuilding the env files after losing the host
The secrets manager holds the five values (`SOC_DB_SUPERUSER_PASSWORD`,
`SOC_DB_OWNER_PASSWORD`, `SOC_DB_INGEST_PASSWORD`, `SOC_INGEST_LC_SLUG`,
`SOC_INGEST_LC_HMAC`). With them exported in the root shell (for example through the
secrets manager's CLI `run` command), on a host whose `/srv/soc/env/` lacks the three
files:

    /opt/soc-platform/deploy/init-secrets.sh --restore

It rebuilds the same three files byte for byte, prints nothing secret, and also
refuses to overwrite. Use it with a restored `pgdata`: the passwords must match the
ones the data directory was created with.

## On the host (Stage A)

PostgreSQL 16 runs as the `db` service in `deploy/compose.yml` (profile `db`, turned
on by `deploy.sh` when the secret files exist). It lives on an **internal** compose
network that only `api`, `db`, the one-off `migrate` job and the optional `worker` join. The tunnel is not
on it. The only thing published on the host is **`127.0.0.1:5432`**, for the console
(which runs on the host network and reads cases as `soc_console`): Docker publishes no
port from an internal-only network, so `db` also joins `dbhost`, a bridge nothing else is
on and which has no outbound NAT. Only processes on the host itself can use that port;
no container can (checked in `scripts/test-db-stack.sh`). The `postgres` superuser is
refused on it as everywhere else. The data directory is `/srv/soc/pgdata` (uid 999, mode 700).

| File (mode 600) | Holds | Read by |
|---|---|---|
| `env/db.env` | `POSTGRES_PASSWORD` (superuser, used once at first start) and `SOC_DB_OWNER_PASSWORD` | `db` |
| `env/db-owner.env` | `SOC_MIGRATE_URL` (the `soc_owner` URL, host `db`) and `SOC_INGEST_DB_PASSWORD` | `migrate` |
| `env/ingest.env` | the webhook secrets and the `soc_ingest` URL (same password) | `api` |

The pager worker adds two more (created by `deploy/init-worker.sh`, see below) and one
optional, non-secret file:

| File (mode 600) | Holds | Read by |
|---|---|---|
| `env/worker.env` | `SOC_NTFY_TOPIC` and the `soc_worker` URL | `worker` |
| `env/worker-owner.env` | `SOC_WORKER_DB_PASSWORD` (the migration job gives `soc_worker` its login) | `migrate` |
| `env/policy.env` (optional) | `SOC_PAGE_POLICY={"<category>": <0-5>, ...}` (0 = case, no push); also `SOC_PAGE_CAP` (1-1000, default 10) and `SOC_PAGE_CAP_WINDOW_SECONDS` (60-86400, default 600); a value outside those bounds stops the worker at start instead of silencing it | `worker` |

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

`logins` also gives `soc_console` its login (5-connection cap) when
`SOC_CONSOLE_DB_PASSWORD` is set, under the same rules as the worker's (optional, a set
but too-short value stops the deploy).

`logins` also gives `soc_worker` its login (5-connection cap) when
`SOC_WORKER_DB_PASSWORD` is set in `db-owner.env`; with it unset the step is skipped,
so a host without the worker deploys as before. A set but too-short value stops the
deploy (exit 2), like the ingest password.

## Cases and the page outbox (worker functions)

- `assign_cases(batch, policy)`: each alert with no case joins an **open case of the
  same client, rule and host whose latest alert is less than 60 minutes older than it**,
  or opens a new case. Alert times are compared with each other, never with `now()`, so
  a backlog after downtime groups the same way live traffic would. One caller at a time
  (advisory lock). A page row is queued only when a case **opens**; `policy` maps the
  detection category (`raw->>'cat'`) to an ntfy priority 0-5 (0 = case, no page; a bad
  or missing value falls back to the case severity: info 0, low 3, medium 4, high and
  critical 5). Unassigned alerts become at least `medium` and always page at 4 or more.
- `claim_pages(batch)`: due `pending` pages, highest priority first. Taking the claim
  is a two-minute lease (`attempts + 1`, `next_attempt_at` pushed out) in the same
  statement, with `FOR UPDATE SKIP LOCKED`, so two workers never send one page twice and
  a worker that dies leaves a page that is due again after the lease. Returns only what
  a push needs: priority, client slug, rule, host (64 chars), the LimaCharlie detection
  link (only when it starts with `https://app.limacharlie.io/`), the first 8 characters
  of the case id and the detection time. Never the raw payload.
- `finish_page(id, outcome, error)`: `sent`; `retry` (network error, 5xx, 429) backs off
  10 s, 30 s, 2 m, 5 m, then every 15 m, and becomes `failed` (`gave_up`) once the page is
  a day old; `fail` (any other 4xx) stops at once. `last_error` is a short lowercase code,
  never a response body.
- `heartbeat_counts(since)`: alerts received, cases opened, pages sent and failed since a
  time, failed pages in the last 24 h, and the age in seconds of the oldest pending page
  and the oldest alert still without a case (what the STALE push watches).
- `worker_state_get/set`: a small key/value table so a restart does not repeat a push.

**Expand, then contract.** A rollback swaps the image only; it never runs a
downgrade. So every migration must keep working with the previous release's code:
add columns and tables first, remove or rename in a later release once nothing old
runs. A migration that breaks the previous image breaks the rollback.

A manual rollback (`deploy.sh <older tag>`) runs the older image's migration job against
a schema a newer release already moved forward. From `0002` on, `soc_api.db upgrade`
sees that the database's revision is unknown to it, prints `database is at revision
..., newer than this release; not migrating` and carries on (logins still run), so the
rollback is not refused. Images built before this change do not have that guard: to go
back to one of them, swap `image.env` by hand instead of running `deploy.sh`.

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

## The pager worker on the host

`deploy/compose.yml` has a `worker` service (profile `worker`): alerts become cases, cases
become phone pushes (ntfy), plus a weekly "SOC OK" push (Sunday 18:00 America/New_York) and
a "SOC STALE" push when a page has waited over ten minutes, a page failed in the last day,
the caser is behind, or the worker has not reached the database for over ten minutes (that
one goes straight to the push server, since every other check needs the database). Each
reason pushes at most once per six hours. It is on the internal `db`
network and on `egress` (outbound), never on `default` (the tunnel's network), publishes
nothing and has no `depends_on`: a database outage does not fail a deploy, the loop retries.
`deploy.sh` and `soc-compose.sh` turn the profile on exactly when `env/worker.env` exists
and the host has a database; a worker file without a database, or an empty one, is refused
before anything changes.

**Set it up (root on the host, once, after `init-secrets.sh`):**

    deploy/init-worker.sh

It writes `env/worker.env` and `env/worker-owner.env` (mode 600), never overwrites, and
prints once: the topic to subscribe the phone to (in the ntfy app, default server) and a
`NAME=value` block for the secrets manager's folder `/soc` (`SOC_NTFY_TOPIC`,
`SOC_DB_WORKER_PASSWORD`). Do not paste that output into chat. After saving it, clear the
terminal and its scrollback, then run `deploy.sh`: the migration job gives `soc_worker` its
login and the worker starts. Lost host: `init-worker.sh --restore` rebuilds both files from
`SOC_NTFY_TOPIC` and `SOC_DB_WORKER_PASSWORD` in the environment.

**Checks:**

    deploy/soc-compose.sh ps                              # worker healthy
    deploy/soc-compose.sh logs --since 10m worker         # page outcome=..., caser alerts=...
    deploy/soc-compose.sh exec -T worker python -m soc_api.worker ok-now   # send the OK push now

**Operating it.** A push that failed for good is `status = 'failed'` in `notification`
(`last_error` is a short code such as `http_400`) and raises the STALE push. The send
timeout is ten seconds, far under the two-minute claim lease. If the push server is down
the worker keeps retrying on the schedule above and gives up after a day. To change who
is paged how loudly, edit `env/policy.env` and restart the worker. To rotate the topic:
make a new one by hand (any 16-64 characters of letters, digits, `-`, `_`), put it in
`worker.env` and the secrets manager, restart the worker and subscribe the phone to it.

**Rollback.** A rollback swaps the image only. An image from before the worker existed has
no `soc_api.worker`: move `env/worker.env` aside first, or the worker will crash-loop
(harmless, but noisy).

**Tests.** `scripts/test-db-stack.sh` runs a real alert through the worker to a fake push
server on the worker's own network and checks: one push per case, nothing for a repeat in
the same case, a new rule is a new push, the topic is only in the push body (never in the
worker's log), the worker is on the `db` and `egress` networks only, and `soc_worker` can
log in but cannot read the alert payload.

## Case states, Ack and Close (migration 0004)

A case is `open`, `acknowledged` or `closed` (the table checks it, and that a closed case has
a close time and no other has). `ack_case(id, login)` moves open to acknowledged, marks the
case's pages acknowledged (so nothing is re-sent for it) and writes one `acked` event; it is
idempotent and returns `acked`, `already`, `closed`, `not_found` or `invalid_login`.
`close_case(id, login, note)` needs a note of 1-2000 characters, closes the case, marks its
pages acknowledged and writes one `closed` event. Only logins shaped like a sign-in name
reach the audit trail (checked in the function). **An acknowledged case still collects new
alerts for its group** (acknowledging stops the buzzing, not the record); only a closed case
stops, and the next matching alert opens a new case and a new page. Events get their own
timestamps (one transaction's `now()` is constant), so a case history has one order.

`list_cases(status, limit)`: `active` (open and acknowledged, the default), `open`,
`acknowledged`, `closed` or `all`; limit 1-500. A rollback to a release from before
`0004` keeps working (it only writes `open`); `alembic downgrade` removes the functions,
the checks and the wider grouping.
