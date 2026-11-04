#!/usr/bin/env bash
# Restore the database from an encrypted backup set (made by backup.sh). Run as root on the
# Stage A host, on a host whose stack is not running:
#
#   restore.sh <set>
#
# <set> is the name of a set in $SOC_STATE_DIR/backups (soc-20261104T061700Z), or the path
# of its .sha256 file when the set was copied from somewhere else (the NAS archive). The
# three files of a set must be together: .dump.age, .globals.sql.age and .sha256.
#
# What it does, in order:
#   1. checks the set's checksums BEFORE anything is decrypted;
#   2. asks for the age private key at the terminal, hidden. The key is never an argument,
#      never in the environment and never written to a file: it goes to `age` on its
#      standard input and is forgotten as soon as both files are decrypted;
#   3. starts the database container (empty data directory: the image creates soc_owner and
#      an empty soc), checks the dump is readable;
#   4. REFUSES unless soc is empty (no rows in any table but the seeded Unassigned client,
#      the migration record and the backup marker) and nothing but the database container
#      is running. It drops and recreates soc, so it must never run against real data;
#   5. creates the roles (without passwords: the backup holds none), recreates soc and loads
#      the dump in one transaction;
#   6. runs the normal migration job, which is a no-op on the same version and gives each
#      login its password again from the owner files in env/. A login whose owner file is
#      missing has none and cannot connect until it is restored (init-*.sh --restore);
#   7. starts the public app and the console, and nothing else: no tunnel, no pager worker,
#      no catch-up worker. Check the data, then bring up the rest with deploy.sh.
# While it runs, backup.sh is locked out (same lock). If a step fails after soc was dropped,
# soc is left empty again so the same command can be run once more.
#
# Plain files exist only in a mode-700 temporary folder in $SOC_STATE_DIR, removed on every
# exit. One line is printed: `restore outcome=ok set=... alerts=N cases=N revision=...`, or
# `restore outcome=failed step=... reason=...` on stderr with a non-zero exit. Database error
# text is never printed (it can quote rows).
#
# Environment: SOC_STATE_DIR (default /srv/soc). SOC_INIT_TEST=1 is for tests only: it skips
# the root check, reads the key from standard input instead of the terminal, is refused for
# root, and is the only way to swap in SOC_COMPOSE, SOC_RESTORE_AGE, SOC_RESTORE_TRIES and
# SOC_RESTORE_SLEEP.
set -euo pipefail

if [[ -n "${SOC_INIT_TEST:-}" && "$EUID" -eq 0 ]]; then
  echo "restore outcome=failed step=start reason=SOC_INIT_TEST_refused_for_root" >&2
  exit 1
fi
if [[ -z "${SOC_INIT_TEST:-}" && "$EUID" -ne 0 ]]; then
  echo "restore outcome=failed step=start reason=run_as_root" >&2
  exit 1
fi
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

HERE="$(cd "$(dirname "$0")" && pwd)"
STATE="${SOC_STATE_DIR:-/srv/soc}"
BACKUPS="$STATE/backups"

COMPOSE="$HERE/soc-compose.sh"
AGE="age"
TRIES=60
SLEEP=2
if [[ -n "${SOC_INIT_TEST:-}" ]]; then
  COMPOSE="${SOC_COMPOSE:-$COMPOSE}"
  AGE="${SOC_RESTORE_AGE:-$AGE}"
  TRIES="${SOC_RESTORE_TRIES:-$TRIES}"
  SLEEP="${SOC_RESTORE_SLEEP:-$SLEEP}"
fi

STEP=start
fail() { echo "restore outcome=failed step=$STEP reason=$1" >&2; exit 1; }

[[ $# -eq 1 ]] || fail "usage_restore.sh_<set-name-or-path-to-.sha256>"
[[ "$TRIES" =~ ^[0-9]+$ && "$SLEEP" =~ ^[0-9]+$ ]] || fail "bad_wait_settings"

NAME_RE='^soc-[0-9]{8}T[0-9]{6}Z$'
UNASSIGNED="00000000-0000-4000-8000-000000000001"

sha256_of() { # file -> hex digest
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# --- which set -------------------------------------------------------------------------
STEP=set
ARG="$1"
if [[ "$ARG" =~ $NAME_RE ]]; then
  DIR="$BACKUPS"
  NAME="$ARG"
elif [[ "$ARG" == *.sha256 ]]; then
  [[ -f "$ARG" && ! -L "$ARG" ]] || fail "set_checksum_file_not_found"
  DIR="$(cd "$(dirname "$ARG")" && pwd)"
  NAME="$(basename "$ARG" .sha256)"
  [[ "$NAME" =~ $NAME_RE ]] || fail "set_name_must_look_like_soc-<UTC_time>"
else
  fail "usage_restore.sh_<set-name-or-path-to-.sha256>"
fi
DUMP_AGE="$DIR/$NAME.dump.age"
GLOBALS_AGE="$DIR/$NAME.globals.sql.age"
SUMS="$DIR/$NAME.sha256"
for f in "$DUMP_AGE" "$GLOBALS_AGE" "$SUMS"; do
  [[ -f "$f" && ! -L "$f" && -s "$f" ]] || fail "set_file_missing_or_empty_${f##*/}"
done

# The host must be set up the way deploy.sh expects, and the data directory must be there.
for f in "$STATE/env/db.env" "$STATE/env/db-owner.env"; do
  [[ -s "$f" ]] || fail "missing_${f##*/}_run_init-secrets.sh_--restore"
done
[[ -d "$STATE/pgdata" ]] || fail "missing_pgdata_run_init-secrets.sh_--restore"
command -v "$AGE" >/dev/null 2>&1 || fail "age_is_not_installed"

# --- the checksums, before anything is decrypted ---------------------------------------
STEP=checksum
LINES="$(wc -l < "$SUMS" | tr -d ' ')"
[[ "$LINES" == 2 ]] || fail "checksum_file_must_have_two_lines"
check_line() { # file-name -> 0 if the sums file says exactly one good digest for it, and it matches
  local want got
  want="$(awk -v f="$1" 'NF == 2 && $2 == f && $1 ~ /^[0-9a-f]+$/ && length($1) == 64 { print $1 }' "$SUMS")"
  [[ -n "$want" && "$(printf '%s\n' "$want" | wc -l | tr -d ' ')" == 1 ]] || return 1
  got="$(sha256_of "$DIR/$1")"
  [[ "$got" == "$want" ]]
}
check_line "$NAME.dump.age" || fail "dump_checksum_does_not_match_damaged_or_changed"
check_line "$NAME.globals.sql.age" || fail "roles_checksum_does_not_match_damaged_or_changed"

# --- the key, typed ------------------------------------------------------------------
STEP=key
KEY=""
if [[ -n "${SOC_INIT_TEST:-}" ]]; then
  IFS= read -r KEY || true
else
  [[ -r /dev/tty ]] || fail "no_terminal_to_type_the_key_into"
  IFS= read -rs -p "age private key (typing is hidden): " KEY < /dev/tty || true
  echo >&2
fi
[[ "$KEY" =~ ^AGE-SECRET-KEY-1[0-9A-Z]{50,}$ ]] || fail "that_is_not_an_age_private_key"

# --- one at a time, and no backup while this runs ------------------------------------------
STEP=lock
umask 077
mkdir -p "$BACKUPS"
chmod 700 "$BACKUPS"
LOCK="$BACKUPS/.lock"
if ! mkdir "$LOCK" 2>/dev/null; then
  OLD="$(cat "$LOCK/pid" 2>/dev/null || true)"
  if [[ "$OLD" =~ ^[0-9]+$ ]] && kill -0 "$OLD" 2>/dev/null; then
    fail "a_backup_or_restore_is_running"
  fi
  rm -rf "$LOCK"
  mkdir "$LOCK" 2>/dev/null || fail "a_backup_or_restore_is_running"
fi
echo "$$" > "$LOCK/pid"

TMP=""
RESET_DB=""
cleanup() {
  local rc=$?
  KEY=""
  if [[ $rc -ne 0 && -n "$RESET_DB" ]]; then
    # soc was dropped and not completely loaded: leave an empty one so this can be run again
    "$COMPOSE" exec -T db psql -U postgres -d postgres -v ON_ERROR_STOP=1 -qAt >/dev/null 2>&1 <<'SQL' || true
DROP DATABASE IF EXISTS soc WITH (FORCE);
CREATE DATABASE soc OWNER soc_owner TEMPLATE template0;
SQL
  fi
  [[ -n "$TMP" ]] && rm -rf "$TMP"
  rm -rf "$LOCK"
  exit "$rc"
}
trap cleanup EXIT

rm -rf "$STATE"/.restore.*
TMP="$(mktemp -d "$STATE/.restore.XXXXXX")"
chmod 700 "$TMP"

# --- decrypt -------------------------------------------------------------------------
STEP=decrypt
decrypt() { # in out
  printf '%s\n' "$KEY" | "$AGE" -d -i - -o "$2" "$1" >/dev/null 2>&1
}
decrypt "$DUMP_AGE" "$TMP/soc.dump" || fail "could_not_decrypt_wrong_key_or_damaged_file"
decrypt "$GLOBALS_AGE" "$TMP/globals.sql" || fail "could_not_decrypt_wrong_key_or_damaged_file"
KEY="" # not needed again
[[ -s "$TMP/soc.dump" && -s "$TMP/globals.sql" ]] || fail "decrypted_file_is_empty"

# --- the database container ----------------------------------------------------------
STEP=database
"$COMPOSE" up -d db >/dev/null 2>&1 || fail "could_not_start_the_database"
ready=""
for ((i = 0; i < TRIES; i++)); do
  if "$COMPOSE" exec -T db pg_isready -q -h 127.0.0.1 -U soc_owner -d soc >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep "$SLEEP"
done
[[ -n "$ready" ]] || fail "database_did_not_become_healthy"

psql_pg() { "$COMPOSE" exec -T db psql -U postgres -v ON_ERROR_STOP=1 -qAt "$@"; }

STEP=verify
"$COMPOSE" exec -T db pg_restore --list < "$TMP/soc.dump" > "$TMP/soc.list" 2>/dev/null \
  || fail "dump_is_not_readable"
grep -q 'TABLE' "$TMP/soc.list" || fail "dump_lists_no_tables"
grep -q 'CREATE ROLE' "$TMP/globals.sql" || fail "roles_dump_has_no_roles"
if grep -Eqi "PASSWORD +'" "$TMP/globals.sql"; then
  fail "roles_dump_contains_a_password"
fi
# The roles file is replayed as the superuser, so every line must be one of the forms
# pg_dumpall --globals-only writes (checked against the pinned image): comments, SET, the
# \restrict guard, CREATE ROLE name;, ALTER ROLE name WITH <flags>;, ALTER ROLE name SET
# <setting>, GRANT role TO role. Anything else (a psql meta-command such as \!, a second
# statement on a line) is refused. Only the superuser may be given SUPERUSER, BYPASSRLS or
# REPLICATION, and no role is given a built-in pg_* role (pg_execute_server_program runs
# programs on the database host): the platform grants none, and a role that gained one here
# would step around every policy.
BAD="$(awk '
  BEGIN { id = "[A-Za-z_][A-Za-z0-9_]*"; val = "('\''[^'\'';]*'\''|[A-Za-z0-9_.$-]+)" }
  /^$/ || /^--/ { next }
  /^\\(restrict|unrestrict) [A-Za-z0-9]+$/ { next }
  /^SET [a-z_]+ = [A-Za-z0-9_'\''.-]+;$/ { next }
  $0 ~ "^CREATE ROLE " id ";$" { next }
  $0 ~ "^ALTER ROLE " id " WITH( [A-Z]+| CONNECTION LIMIT -?[0-9]+| VALID UNTIL '\''[^'\'';]*'\'')*;$" {
    if ($3 != "postgres" && $0 ~ / (SUPERUSER|BYPASSRLS|REPLICATION)( |;)/) { bad++ }
    next }
  $0 ~ "^ALTER ROLE " id "( IN DATABASE " id ")? SET [a-z_.]+ (TO|=) " val "(, " val ")*;$" { next }
  $0 ~ "^GRANT " id " TO " id "( WITH [A-Z]+ (TRUE|FALSE|OPTION)(, [A-Z]+ (TRUE|FALSE|OPTION))*)?( GRANTED BY " id ")?;$" {
    if ($2 ~ /^pg_/) { bad++ }
    next }
  { bad++ }
  END { print bad + 0 }' "$TMP/globals.sql")"
[[ "$BAD" == 0 ]] || fail "roles_dump_has_a_line_this_does_not_understand"

# --- refuse unless this is an empty database on a stopped stack ---------------------------
STEP=empty
RUNNING="$("$COMPOSE" ps --status running --services 2>/dev/null)" || fail "could_not_list_running_services"
if [[ -n "$(printf '%s\n' "$RUNNING" | grep -v -x -e db -e '' || true)" ]]; then
  fail "stack_is_running_stop_it_first_soc-compose.sh_down"
fi
EXISTS="$(psql_pg -d postgres -c "SELECT count(*) FROM pg_database WHERE datname = 'soc'" 2>/dev/null)" \
  || fail "cannot_read_the_database"
ROWS=0
if [[ "$EXISTS" == 1 ]]; then
  ROWS="$(psql_pg -d soc 2>/dev/null <<SQL
WITH t AS (
  SELECT n.nspname AS s, c.relname AS r
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE c.relkind IN ('r', 'p')
    AND n.nspname NOT IN ('pg_catalog', 'information_schema')
    AND n.nspname NOT LIKE 'pg_toast%'
    AND c.relname NOT IN ('alembic_version', 'backup_state'))
SELECT coalesce(sum(((xpath('/row/c/text()', query_to_xml(
  format('SELECT count(*) AS c FROM %I.%I %s', s, r,
         CASE WHEN r = 'client' THEN 'WHERE id <> ''$UNASSIGNED''' ELSE '' END),
  false, true, '')))[1])::text::bigint), 0)
FROM t
SQL
  )" || fail "cannot_read_the_database"
fi
[[ "$ROWS" =~ ^[0-9]+$ ]] || fail "cannot_read_the_database"
[[ "$ROWS" == 0 ]] || fail "database_already_has_data_refusing_to_overwrite"

# --- roles, then the database ------------------------------------------------------------
STEP=roles
# pg_dumpall writes CREATE ROLE for every role, including the two that already exist (the
# superuser and the owner the image made). Make each "create if missing"; the ALTER ROLE and
# GRANT lines that follow then apply to all of them and carry no password.
awk '
  /^CREATE ROLE [A-Za-z_][A-Za-z0-9_]*;$/ {
    name = $3; sub(/;$/, "", name)
    printf "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '\''%s'\'') THEN CREATE ROLE %s; END IF; END $$;\n", name, name
    next }
  { print }' "$TMP/globals.sql" > "$TMP/globals.safe.sql"
"$COMPOSE" exec -T db psql -U postgres -d postgres -v ON_ERROR_STOP=1 -q \
  < "$TMP/globals.safe.sql" >/dev/null 2>&1 || fail "could_not_create_the_roles"

STEP=load
RESET_DB=1
psql_pg -d postgres >/dev/null 2>&1 <<'SQL' || fail "could_not_recreate_the_database"
DROP DATABASE IF EXISTS soc WITH (FORCE);
CREATE DATABASE soc OWNER soc_owner TEMPLATE template0;
SQL
"$COMPOSE" exec -T db pg_restore -U postgres -d soc --exit-on-error --single-transaction \
  < "$TMP/soc.dump" >/dev/null 2>&1 || fail "pg_restore_failed"
RESET_DB="" # loaded

# --- logins, from the owner files -----------------------------------------------------------
STEP=migrate
"$COMPOSE" run --rm migrate >/dev/null 2>&1 || fail "migration_job_failed"

STEP=check
SUMMARY="$(psql_pg -d soc -F ' ' -c \
  "SELECT (SELECT count(*) FROM alert), (SELECT count(*) FROM soc_case), (SELECT version_num FROM alembic_version)" \
  2>/dev/null)" || fail "cannot_read_the_restored_database"
read -r ALERTS CASES REVISION <<< "$SUMMARY"
[[ "$ALERTS" =~ ^[0-9]+$ && "$CASES" =~ ^[0-9]+$ && -n "$REVISION" ]] || fail "unexpected_summary"

# --- the app and the console only -----------------------------------------------------------
STEP=start-app
"$COMPOSE" up -d api console >/dev/null 2>&1 || fail "could_not_start_the_app_and_console"

echo "restore outcome=ok set=$NAME alerts=$ALERTS cases=$CASES revision=$REVISION"
