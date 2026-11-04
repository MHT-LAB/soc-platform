#!/usr/bin/env bash
# Take an encrypted copy of the database. Run as root on the Stage A host, by the systemd
# timer in deploy/systemd (every six hours) or by hand:
#
#   backup.sh
#
# What it does, in order:
#   1. refuses unless the database is healthy and there is room to write;
#   2. dumps the database and the roles (without their passwords) through the database
#      container's own socket, the only place the superuser works;
#   3. checks both dumps are readable before they count;
#   4. encrypts both to the public key in env/backup-age.pub (init-backup.sh): the host can
#      encrypt but never decrypt; the private key is in the secrets manager and on paper;
#   5. writes a checksum file last, so a set is complete exactly when its checksum exists;
#   6. keeps the newest SOC_BACKUP_KEEP complete sets (default 8) and removes the rest;
#   7. records the good dump in the database (backup_mark_ok, as the superuser over the
#      same socket), which is what the pager's "backup older than 13 hours" check reads.
#
# Files, in $SOC_STATE_DIR/backups (mode 700), each mode 600:
#   soc-<UTC time>.dump.age   soc-<UTC time>.globals.sql.age   soc-<UTC time>.sha256
# The plain dumps exist only in a mode-700 temporary directory inside that folder and are
# removed on every exit. It never overwrites a file. A failure prints one line to stderr
# and exits non-zero; success prints one line. Nothing secret is ever printed.
#
# Environment: SOC_STATE_DIR (default /srv/soc), SOC_BACKUP_KEEP (2-100, default 8),
# SOC_BACKUP_MIN_FREE_MB (default 500). SOC_INIT_TEST=1 is for tests only: it skips the
# root check, is refused for root, and is the only way to swap in SOC_COMPOSE, SOC_BACKUP_AGE
# and SOC_BACKUP_NOW.
set -euo pipefail

if [[ -n "${SOC_INIT_TEST:-}" && "$EUID" -eq 0 ]]; then
  echo "backup outcome=failed step=start reason=SOC_INIT_TEST_refused_for_root" >&2
  exit 1
fi
if [[ -z "${SOC_INIT_TEST:-}" && "$EUID" -ne 0 ]]; then
  echo "backup outcome=failed step=start reason=run_as_root" >&2
  exit 1
fi
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

HERE="$(cd "$(dirname "$0")" && pwd)"
STATE="${SOC_STATE_DIR:-/srv/soc}"
PUB_FILE="$STATE/env/backup-age.pub"
BACKUPS="$STATE/backups"
KEEP="${SOC_BACKUP_KEEP:-8}"
MIN_FREE_MB="${SOC_BACKUP_MIN_FREE_MB:-500}"

COMPOSE="$HERE/soc-compose.sh"
AGE="age"
NOW_OVERRIDE=""
if [[ -n "${SOC_INIT_TEST:-}" ]]; then
  COMPOSE="${SOC_COMPOSE:-$COMPOSE}"
  AGE="${SOC_BACKUP_AGE:-$AGE}"
  NOW_OVERRIDE="${SOC_BACKUP_NOW:-}"
fi

STEP=start
fail() { echo "backup outcome=failed step=$STEP reason=$1" >&2; exit 1; }

[[ "$KEEP" =~ ^[0-9]+$ ]] && (( KEEP >= 2 && KEEP <= 100 )) || fail "SOC_BACKUP_KEEP_must_be_2_to_100"
[[ "$MIN_FREE_MB" =~ ^[0-9]+$ ]] || fail "SOC_BACKUP_MIN_FREE_MB_must_be_a_number"

STAMP_RE='^[0-9]{8}T[0-9]{6}Z$'
STAMP="${NOW_OVERRIDE:-$(date -u +%Y%m%dT%H%M%SZ)}"
[[ "$STAMP" =~ $STAMP_RE ]] || fail "bad_timestamp"

sha256_of() { # file -> hex digest
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# --- the key and the folder ------------------------------------------------------------
STEP=key
[[ -s "$PUB_FILE" ]] || fail "missing_env/backup-age.pub_run_init-backup.sh"
PUB="$(head -n1 "$PUB_FILE")"
[[ "$PUB" =~ ^age1[0-9a-z]{50,}$ ]] || fail "env/backup-age.pub_is_not_an_age_public_key"
[[ "$(wc -l < "$PUB_FILE" | tr -d ' ')" -le 1 ]] || fail "env/backup-age.pub_has_more_than_one_line"
command -v "$AGE" >/dev/null 2>&1 || fail "age_is_not_installed"

STEP=folder
umask 077
mkdir -p "$BACKUPS"
chmod 700 "$BACKUPS"

# One run at a time: mkdir is atomic. A lock left by a killed run is taken over when its
# process is gone.
LOCK="$BACKUPS/.lock"
if ! mkdir "$LOCK" 2>/dev/null; then
  OLD="$(cat "$LOCK/pid" 2>/dev/null || true)"
  if [[ "$OLD" =~ ^[0-9]+$ ]] && kill -0 "$OLD" 2>/dev/null; then
    fail "another_backup_is_running"
  fi
  rm -rf "$LOCK"
  mkdir "$LOCK" 2>/dev/null || fail "another_backup_is_running"
fi
echo "$$" > "$LOCK/pid"

TMP=""
MOVED=""
cleanup() {
  local rc=$?
  [[ -n "$TMP" ]] && rm -rf "$TMP"
  if [[ $rc -ne 0 && -n "$MOVED" ]]; then # a set that did not finish is not a set
    while IFS= read -r f; do [[ -n "$f" ]] && rm -f "$f"; done <<< "$MOVED"
  fi
  rm -rf "$LOCK"
  exit "$rc"
}
trap cleanup EXIT

# Leftovers of an earlier run that died: temporary folders, and data files with no checksum.
rm -rf "$BACKUPS"/.tmp.*
for f in "$BACKUPS"/soc-*.dump.age "$BACKUPS"/soc-*.globals.sql.age; do
  [[ -e "$f" ]] || continue
  base="${f##*/}"
  base="${base%%.*}"
  [[ -e "$BACKUPS/$base.sha256" ]] || rm -f "$f"
done

STEP=space
FREE_KB="$(df -Pk "$BACKUPS" | awk 'NR==2 {print $4}')"
[[ "$FREE_KB" =~ ^[0-9]+$ ]] || fail "cannot_read_free_space"
(( FREE_KB / 1024 >= MIN_FREE_MB )) || fail "not_enough_free_space"

# --- dump ------------------------------------------------------------------------------
STEP=database
"$COMPOSE" exec -T db pg_isready -q -h 127.0.0.1 -U soc_owner -d soc >/dev/null 2>&1 \
  || fail "database_not_healthy"

TMP="$(mktemp -d "$BACKUPS/.tmp.XXXXXX")"
chmod 700 "$TMP"

STEP=dump
"$COMPOSE" exec -T db pg_dump -U postgres -d soc -Fc > "$TMP/soc.dump" 2>/dev/null \
  || fail "pg_dump_failed"
STEP=roles
"$COMPOSE" exec -T db pg_dumpall -U postgres --globals-only --no-role-passwords \
  > "$TMP/globals.sql" 2>/dev/null || fail "pg_dumpall_failed"

# --- check the dumps -------------------------------------------------------------------
STEP=verify
[[ -s "$TMP/soc.dump" ]] || fail "dump_is_empty"
"$COMPOSE" exec -T db pg_restore --list < "$TMP/soc.dump" > "$TMP/soc.list" 2>/dev/null \
  || fail "dump_is_not_readable"
grep -q 'TABLE' "$TMP/soc.list" || fail "dump_lists_no_tables"
[[ -s "$TMP/globals.sql" ]] || fail "roles_dump_is_empty"
grep -q 'CREATE ROLE' "$TMP/globals.sql" || fail "roles_dump_has_no_roles"
# the passwords must never travel: a role line with one means the flag did not work
if grep -Eqi "PASSWORD +'" "$TMP/globals.sql"; then
  fail "roles_dump_contains_a_password"
fi

# --- encrypt, then put in place --------------------------------------------------------
STEP=encrypt
"$AGE" -R "$PUB_FILE" -o "$TMP/soc.dump.age" "$TMP/soc.dump" || fail "age_failed"
"$AGE" -R "$PUB_FILE" -o "$TMP/globals.sql.age" "$TMP/globals.sql" || fail "age_failed"
[[ -s "$TMP/soc.dump.age" && -s "$TMP/globals.sql.age" ]] || fail "age_wrote_nothing"

STEP=store
NAME="soc-$STAMP"
DUMP_OUT="$BACKUPS/$NAME.dump.age"
GLOBALS_OUT="$BACKUPS/$NAME.globals.sql.age"
SUM_OUT="$BACKUPS/$NAME.sha256"
for f in "$DUMP_OUT" "$GLOBALS_OUT" "$SUM_OUT"; do
  [[ ! -e "$f" ]] || fail "${NAME}_already_exists_never_overwrites"
done

place() { # source target
  mv "$1" "$2"
  MOVED="$MOVED
$2"
  chmod 600 "$2"
}
place "$TMP/soc.dump.age" "$DUMP_OUT"
place "$TMP/globals.sql.age" "$GLOBALS_OUT"
printf '%s  %s\n%s  %s\n' \
  "$(sha256_of "$DUMP_OUT")" "$NAME.dump.age" \
  "$(sha256_of "$GLOBALS_OUT")" "$NAME.globals.sql.age" > "$TMP/sums"
place "$TMP/sums" "$SUM_OUT" # last: its presence is what makes the set complete
BYTES="$(wc -c < "$DUMP_OUT" | tr -d ' ')"

# --- keep the newest few ---------------------------------------------------------------
STEP=retention
SETS=()
while IFS= read -r line; do
  [[ -n "$line" ]] && SETS+=("$line")
done < <(cd "$BACKUPS" && ls -1 soc-*.sha256 2>/dev/null | sort -r || true)
KEPT=${#SETS[@]}
if (( KEPT > KEEP )); then
  for old in "${SETS[@]:KEEP}"; do
    base="${old%.sha256}"
    rm -f "$BACKUPS/$base.dump.age" "$BACKUPS/$base.globals.sql.age" "$BACKUPS/$base.sha256"
  done
  KEPT=$KEEP
fi

# The set is complete and checked: keep it whatever happens next. Then tell the database,
# so the pager knows the last good dump is fresh. If that call fails the run fails (the
# timer shows it, and the pager goes stale in 13 hours), but the good set stays.
MOVED=""
STEP=mark
[[ "$BYTES" =~ ^[0-9]+$ ]] && (( BYTES > 0 )) || fail "bad_dump_size"
"$COMPOSE" exec -T db psql -U postgres -d soc -v ON_ERROR_STOP=1 -qAt \
  -c "SELECT backup_mark_ok($BYTES)" >/dev/null 2>&1 || fail "could_not_record_the_dump"
echo "backup outcome=ok set=$NAME bytes=$BYTES kept=$KEPT"
