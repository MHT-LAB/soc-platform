#!/usr/bin/env bash
# Proves the backup -> restore path on the real compose services (note 26, row B1c).
#
#   scripts/test-restore-stack.sh <image>      e.g. soc-api:ci
#
# Needs Docker, the `age` package (age and age-keygen on PATH) and a non-root user.
#
# Source host: starts the database, migrates, seeds, adds alerts and cases, takes a backup
# with deploy/backup.sh (real age, real pg_dump) and keeps the set. Then the whole stack and
# its data directory are destroyed.
# Fresh host: only the secret files are rebuilt, with the `--restore` modes of the init
# scripts, then deploy/restore.sh runs with the typed key. Checks: the restored data is
# row-for-row the same (a checksum of every table's rows); roles, grants, policies, owners and
# the schema's access rules are the same (a checksum of them); the login that has an owner
# file works, and the one without does not even with its OLD password (the backup holds no
# password) until its owner file is restored; only the app and the console were started;
# a second restore is refused, whether the stack is up or down, and changes nothing; and
# backup.sh works again on the restored database.
# Every secret here is a throwaway value for containers that live for this run.
set -euo pipefail

IMAGE="${1:?usage: test-restore-stack.sh <image>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
DEPLOY="$HERE/../deploy"
WORK1="$(mktemp -d)"
WORK2="$(mktemp -d)"
KEEP="$(mktemp -d)"
BIN="$(mktemp -d)"
FAILS=0
P=socrestoretest
export SOC_API_IMAGE="$IMAGE" SOC_ENV=prod COMPOSE_PROFILES=db

command -v age > /dev/null && command -v age-keygen > /dev/null \
  || { echo "FAIL - age and age-keygen are needed on PATH"; exit 1; }
AGE_BIN="$(command -v age)"

# The same compose project and files the host uses; the state directory is whichever host
# is current (SOC_STATE_DIR in the environment).
cat > "$BIN/dc" << EOF
#!/bin/bash
export SOC_API_IMAGE="$IMAGE" SOC_ENV=prod COMPOSE_PROFILES=db
exec docker compose -p $P -f "$DEPLOY/compose.yml" "\$@"
EOF
chmod 755 "$BIN/dc"
compose() { "$BIN/dc" "$@"; }
as_root() { docker run --rm --user 0 -v "$1:/w" --entrypoint "$2" "$IMAGE" "${@:3}"; }

cleanup() {
  for w in "$WORK1" "$WORK2"; do
    SOC_STATE_DIR="$w" compose down -v --remove-orphans > /dev/null 2>&1 || true
    as_root "$w" rm -rf /w/pgdata > /dev/null 2>&1 || true
    rm -rf "$w"
  done
  rm -rf "$KEEP" "$BIN"
}
trap cleanup EXIT

pass() { echo "ok   - $*"; }
fail() { echo "FAIL - $*"; FAILS=$((FAILS + 1)); }
rand() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

SQL() { compose exec -T db psql -U postgres -d soc -Atq -c "$1"; }
wait_db() {
  for _ in $(seq 1 60); do
    [[ "$(docker inspect --format '{{.State.Health.Status}}' "$(compose ps -q db)" 2> /dev/null)" == healthy ]] && return 0
    sleep 2
  done
  return 1
}
# One checksum over every row of the tables that hold the SOC's data.
data_fp() {
  compose exec -T db psql -U postgres -d soc -Atq << 'SQL'
SELECT md5(string_agg(x, '|' ORDER BY x)) FROM (
  SELECT 'client:' || t::text AS x FROM client t
  UNION ALL SELECT 'source:' || t::text FROM source t
  UNION ALL SELECT 'alert:' || t::text FROM alert t
  UNION ALL SELECT 'case:' || t::text FROM soc_case t
  UNION ALL SELECT 'event:' || t::text FROM case_event t
  UNION ALL SELECT 'note:' || t::text FROM notification t) s
SQL
}
# One checksum over who can do what: owners, grants, row-level policies, functions, roles
# (never a password) and who is a member of whom.
access_fp() {
  compose exec -T db psql -U postgres -d soc -Atq << 'SQL'
SELECT md5(string_agg(x, '|' ORDER BY x)) FROM (
  SELECT 'rel:' || c.relname || ':' || pg_get_userbyid(c.relowner) || ':' || coalesce(c.relacl::text, '')
         || ':' || c.relrowsecurity::text AS x
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'S', 'v')
  UNION ALL SELECT 'col:' || c.relname || '.' || a.attname || ':' || a.attacl::text
    FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind = 'r' AND a.attnum > 0
      AND NOT a.attisdropped AND a.attacl IS NOT NULL
  UNION ALL SELECT 'fn:' || p.oid::regprocedure::text || ':' || pg_get_userbyid(p.proowner) || ':'
         || coalesce(p.proacl::text, '') || ':' || p.prosecdef::text || ':' || coalesce(p.proconfig::text, '')
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public'
  UNION ALL SELECT 'pol:' || tablename || ':' || policyname || ':' || cmd || ':' || roles::text || ':'
         || coalesce(qual, '') || ':' || coalesce(with_check, '') FROM pg_policies
  UNION ALL SELECT 'role:' || rolname || ':' || rolsuper::text || rolinherit::text || rolcreaterole::text
         || rolcreatedb::text || rolcanlogin::text || rolreplication::text || rolbypassrls::text
         || ':' || rolconnlimit::text FROM pg_roles WHERE rolname NOT LIKE 'pg\_%'
  UNION ALL SELECT 'member:' || r.rolname || '>' || m.rolname
    FROM pg_auth_members am JOIN pg_roles r ON r.oid = am.roleid JOIN pg_roles m ON m.oid = am.member
    WHERE r.rolname NOT LIKE 'pg\_%' AND m.rolname NOT LIKE 'pg\_%'
  UNION ALL SELECT 'schema:' || nspname || ':' || pg_get_userbyid(nspowner) || ':' || coalesce(nspacl::text, '')
    FROM pg_namespace WHERE nspname = 'public') s
SQL
}
# A throwaway container on the database network trying a login: exit 0 if accepted.
login() { # user password
  docker run --rm --network "${P}_db" -e PW="$2" --entrypoint python "$IMAGE" -c "
import os, psycopg
psycopg.connect(host='db', dbname='soc', user='$1', password=os.environ['PW'], connect_timeout=5).close()" > /dev/null 2>&1
}

# ---------------------------------------------------------------- the source host ----------
export SOC_STATE_DIR="$WORK1"
SLUG="lc-$(rand 8)"
SOC_INIT_TEST=1 "$DEPLOY/init-secrets.sh" "$SLUG" soc.example.com > /dev/null 2>&1 \
  && pass "source host: init-secrets.sh" || { fail "init-secrets.sh failed"; exit 1; }
SOC_INIT_TEST=1 "$DEPLOY/init-worker.sh" > /dev/null 2>&1 \
  && pass "source host: init-worker.sh" || { fail "init-worker.sh failed"; exit 1; }
KEYOUT="$(SOC_INIT_TEST=1 SOC_TEST_PATH="$PATH" "$DEPLOY/init-backup.sh" 2>&1)" \
  && pass "source host: init-backup.sh made the age key pair" || { fail "init-backup.sh failed"; exit 1; }
AGE_KEY="$(sed -n 's/^SOC_BACKUP_AGE_KEY=//p' <<< "$KEYOUT")"
AGE_PUB="$(sed -n 's/^SOC_BACKUP_AGE_PUB=//p' <<< "$KEYOUT")"
KEYOUT=""
[[ "$AGE_KEY" == AGE-SECRET-KEY-1* && "$AGE_PUB" == age1* ]] || { fail "no age key pair printed"; exit 1; }
SUPER_PW="$(sed -n 's/^POSTGRES_PASSWORD=//p' "$WORK1/env/db.env")"
OWNER_PW="$(sed -n 's/^SOC_DB_OWNER_PASSWORD=//p' "$WORK1/env/db.env")"
INGEST_PW="$(sed -n 's/^SOC_INGEST_DB_PASSWORD=//p' "$WORK1/env/db-owner.env")"
HMAC="$(sed -n 's/.*\["\([0-9a-f]*\)"\].*/\1/p' "$WORK1/env/ingest.env")"
WORKER_PW="$(sed -n 's/^SOC_WORKER_DB_PASSWORD=//p' "$WORK1/env/worker-owner.env")"
TOPIC="$(sed -n 's/^SOC_NTFY_TOPIC=//p' "$WORK1/env/worker.env")"
as_root "$WORK1" chown 999:999 /w/pgdata
echo 'SOC_CONSOLE_USERS=ci@example.com' > "$WORK1/env/console.env"
chmod 600 "$WORK1/env/console.env"
cat > "$WORK1/seed/smoke.json" << JSON
{"client": {"slug": "smoke", "name": "Smoke Test Co", "status": "internal"},
 "sources": [{"slug": "$SLUG", "type": "limacharlie", "external_id": "00000000-0000-4000-8000-0000000000aa"}]}
JSON

compose up -d db > /dev/null 2>&1
wait_db && pass "source host: db is healthy" || { compose logs db; fail "db did not become healthy"; exit 1; }
compose run --rm migrate > /dev/null 2>&1 && pass "source host: migrations and logins applied" || { fail "migrate failed"; exit 1; }
compose run --rm --entrypoint python migrate -m soc_api.seed /seed/smoke.json > /dev/null 2>&1 \
  && pass "source host: seed loaded" || { fail "seed failed"; exit 1; }

# Alerts through the real ingest function, cases through the real caser function.
for i in 1 2 3 4; do
  SQL "SELECT ingest_alert('$SLUG', '00000000-0000-4000-8000-0000000000aa', 'ev-$i', 'rule-$((i % 2))', 'high', 'summary $i', 'actor', 'T1059', now(), '{\"cat\": \"CAT\", \"routing\": {\"hostname\": \"host-$i\"}}'::jsonb)" > /dev/null
done
SQL "SELECT * FROM assign_cases(100, '{\"CAT\": 3}'::jsonb)" > /dev/null
ALERTS="$(SQL 'SELECT count(*) FROM alert')"
CASES="$(SQL 'SELECT count(*) FROM soc_case')"
[[ "$ALERTS" == 4 && "$CASES" -ge 1 ]] && pass "source host: $ALERTS alerts and $CASES cases written" \
  || { fail "expected 4 alerts and some cases, got $ALERTS and $CASES"; exit 1; }

# A real backup, by the real script, with the real age.
BK="$(SOC_INIT_TEST=1 SOC_BACKUP_AGE="$AGE_BIN" SOC_COMPOSE="$BIN/dc" SOC_BACKUP_MIN_FREE_MB=1 "$DEPLOY/backup.sh" 2>&1)" \
  && pass "source host: backup.sh ok ($BK)" || { echo "$BK"; fail "backup.sh failed"; exit 1; }
SET="$(sed -n 's/.* set=\([^ ]*\) .*/\1/p' <<< "$BK")"
[[ -n "$SET" && -s "$WORK1/backups/$SET.sha256" ]] || { fail "no backup set was written"; exit 1; }
[[ "$(SQL 'SELECT last_bytes IS NOT NULL FROM backup_state')" == t ]] \
  && pass "source host: the database recorded the good dump" || fail "backup_mark_ok did not record the dump"
DATA1="$(data_fp)"
ACCESS1="$(access_fp)"
[[ -n "$DATA1" && -n "$ACCESS1" ]] && pass "source host: data and access checksums taken" || { fail "no checksums"; exit 1; }
login soc_ingest "$INGEST_PW" && login soc_worker "$WORKER_PW" \
  && pass "source host: soc_ingest and soc_worker can log in" || fail "source logins do not work (test setup is broken)"
cp "$WORK1/backups/$SET".* "$KEEP/"

# ---- the host is lost: stack, data directory and every file but the backup set ----------
compose down -v --remove-orphans > /dev/null 2>&1
as_root "$WORK1" rm -rf /w/pgdata
rm -rf "$WORK1"
WORK1="$(mktemp -d)"
[[ -z "$(docker ps -aq --filter "label=com.docker.compose.project=$P")" ]] \
  && pass "the source stack and its data are gone" || fail "the source stack is still there"

# ---------------------------------------------------------------- the fresh host ----------
export SOC_STATE_DIR="$WORK2"
SOC_INIT_TEST=1 SOC_INGEST_LC_SLUG="$SLUG" SOC_DB_SUPERUSER_PASSWORD="$SUPER_PW" \
  SOC_DB_OWNER_PASSWORD="$OWNER_PW" SOC_DB_INGEST_PASSWORD="$INGEST_PW" SOC_INGEST_LC_HMAC="$HMAC" \
  "$DEPLOY/init-secrets.sh" --restore > /dev/null 2>&1 \
  && pass "fresh host: init-secrets.sh --restore" || { fail "init-secrets.sh --restore failed"; exit 1; }
as_root "$WORK2" chown 999:999 /w/pgdata
echo 'SOC_CONSOLE_USERS=ci@example.com' > "$WORK2/env/console.env"
chmod 600 "$WORK2/env/console.env"
SOC_INIT_TEST=1 SOC_BACKUP_AGE_PUB="$AGE_PUB" "$DEPLOY/init-backup.sh" --restore > /dev/null 2>&1 \
  && pass "fresh host: init-backup.sh --restore (public key only)" || { fail "init-backup.sh --restore failed"; exit 1; }
mkdir -p "$WORK2/backups"
cp "$KEEP/$SET".* "$WORK2/backups/"

# the wrong key first: refused, and the database is not touched
WRONG="$(age-keygen 2> /dev/null | grep '^AGE-SECRET-KEY-')"
if printf '%s\n' "$WRONG" | SOC_INIT_TEST=1 SOC_RESTORE_AGE="$AGE_BIN" SOC_COMPOSE="$BIN/dc" \
  "$DEPLOY/restore.sh" "$SET" > /dev/null 2> "$WORK2/err.txt"; then
  fail "restore.sh accepted a wrong key"
else
  grep -q 'step=decrypt' "$WORK2/err.txt" && [[ -z "$(docker ps -aq --filter "label=com.docker.compose.project=$P")" ]] \
    && pass "fresh host: a wrong key is refused before any container starts" \
    || fail "wrong key: unexpected result ($(cat "$WORK2/err.txt"))"
fi
rm -f "$WORK2/err.txt"

OUT="$(printf '%s\n' "$AGE_KEY" | SOC_INIT_TEST=1 SOC_RESTORE_AGE="$AGE_BIN" SOC_COMPOSE="$BIN/dc" \
  "$DEPLOY/restore.sh" "$SET" 2>&1)" \
  && pass "fresh host: restore.sh ok ($OUT)" || { echo "$OUT"; fail "restore.sh failed"; compose logs db | tail -20; exit 1; }
[[ "$OUT" == "restore outcome=ok set=$SET alerts=$ALERTS cases=$CASES revision="* ]] \
  && pass "restore.sh reports the same alert and case counts" || fail "restore.sh summary differs: $OUT"
[[ "$OUT" != *"$AGE_KEY"* && "$OUT" != *"$OWNER_PW"* ]] && pass "restore.sh printed no secret" || fail "restore.sh printed a secret"

[[ "$(SQL 'SELECT last_bytes IS NULL FROM backup_state')" == t ]] \
  && pass "the restored database says no good dump has been taken yet (the pager will, until one is)" \
  || fail "the restored database claims a good dump it does not have"
[[ "$(data_fp)" == "$DATA1" ]] && pass "every row of every table is the same as on the source host" \
  || fail "the restored rows differ from the source"
[[ "$(access_fp)" == "$ACCESS1" ]] && pass "owners, grants, policies, functions, roles and memberships are the same" \
  || fail "the restored access rules differ from the source"

# logins: the one with an owner file works; the one without has no password at all
login soc_owner "$OWNER_PW" && pass "soc_owner can log in (password from db.env)" || fail "soc_owner cannot log in"
login soc_ingest "$INGEST_PW" && pass "soc_ingest can log in (password re-applied from db-owner.env)" \
  || fail "soc_ingest cannot log in after the restore"
login postgres "$SUPER_PW" && fail "the postgres superuser CAN log in over the network" \
  || pass "the postgres superuser is still refused over the network"
[[ "$(SQL "SELECT rolcanlogin AND rolpassword IS NULL FROM pg_authid WHERE rolname = 'soc_worker'")" == t ]] \
  && pass "soc_worker is restored with its login right but NO password (the backup holds none)" \
  || fail "soc_worker has a password it should not have"
login soc_worker "$WORKER_PW" && fail "soc_worker logged in with its OLD password before its owner file was restored" \
  || pass "soc_worker cannot log in with its old password: the backup carries no password"
SOC_INIT_TEST=1 SOC_NTFY_TOPIC="$TOPIC" SOC_DB_WORKER_PASSWORD="$WORKER_PW" "$DEPLOY/init-worker.sh" --restore > /dev/null 2>&1 \
  && compose run --rm migrate > /dev/null 2>&1 \
  && login soc_worker "$WORKER_PW" \
  && pass "after init-worker.sh --restore and the migration job, soc_worker logs in" \
  || fail "soc_worker did not get its login back from its owner file"

# what was started
RUNNING="$(compose ps --status running --services | sort | tr '\n' ' ')"
[[ "$RUNNING" == "api console db " ]] && pass "only db, api and console are running (no tunnel, worker or catch-up worker)" \
  || fail "unexpected services running: $RUNNING"

# a second restore must change nothing
if printf '%s\n' "$AGE_KEY" | SOC_INIT_TEST=1 SOC_RESTORE_AGE="$AGE_BIN" SOC_COMPOSE="$BIN/dc" \
  "$DEPLOY/restore.sh" "$SET" > /dev/null 2> "$WORK2/err.txt"; then
  fail "a second restore ran against a running stack"
else
  grep -q 'stack_is_running' "$WORK2/err.txt" && pass "a second restore is refused while the stack is running" \
    || fail "second restore refused for the wrong reason: $(cat "$WORK2/err.txt")"
fi
compose stop api console > /dev/null 2>&1
if printf '%s\n' "$AGE_KEY" | SOC_INIT_TEST=1 SOC_RESTORE_AGE="$AGE_BIN" SOC_COMPOSE="$BIN/dc" \
  "$DEPLOY/restore.sh" "$SET" > /dev/null 2> "$WORK2/err.txt"; then
  fail "a second restore overwrote a database that has data"
else
  grep -q 'database_already_has_data' "$WORK2/err.txt" && pass "a second restore is refused because the database has data" \
    || fail "second restore refused for the wrong reason: $(cat "$WORK2/err.txt")"
fi
rm -f "$WORK2/err.txt"
[[ "$(data_fp)" == "$DATA1" ]] && pass "and the data is untouched" || fail "the refused restore changed the data"

# The dump is taken before the database is told about it, so a restored database says
# "no good dump yet" (and the pager will say so, until the first backup on the new host).
# and backups work again on the restored database
BK2="$(SOC_INIT_TEST=1 SOC_BACKUP_AGE="$AGE_BIN" SOC_COMPOSE="$BIN/dc" SOC_BACKUP_MIN_FREE_MB=1 \
  SOC_BACKUP_NOW=20991231T235959Z "$DEPLOY/backup.sh" 2>&1)" \
  && pass "backup.sh works on the restored database" || { echo "$BK2"; fail "backup.sh failed after the restore"; }
[[ "$(SQL 'SELECT last_bytes IS NOT NULL FROM backup_state')" == t ]] \
  && pass "and the database records that new dump" || fail "the restored database did not record the new dump"
[[ -z "$(ls -A "$WORK2/backups" | grep -E '^\.(lock|tmp)' || true)" && -z "$(ls -A "$WORK2" | grep '^\.restore\.' || true)" ]] \
  && pass "no lock or temporary folder is left behind" || fail "restore left a lock or a temporary folder"

echo
if [[ "$FAILS" == 0 ]]; then
  echo "all restore checks passed"
else
  echo "$FAILS restore check(s) FAILED"
  exit 1
fi
