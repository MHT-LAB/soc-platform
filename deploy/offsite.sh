#!/usr/bin/env bash
# Send the encrypted backup sets to the off-site restic repository (Backblaze B2). Run as
# root on the Stage A host by soc-offsite.service (started when a backup finishes well, see
# deploy/systemd) or by hand:
#
#   offsite.sh           send what is in $SOC_STATE_DIR/backups
#   offsite.sh --init    create the (empty) repository, once, with the same key
#
# What it does, in order:
#   1. checks env/offsite.env (init-offsite.sh): mode 600, exactly the four expected lines,
#      each one the right shape. Values are never printed;
#   2. checks there is at least one complete set to send;
#   3. takes the same lock as backup.sh and restore.sh (nothing is read while a set is
#      being written);
#   4. runs restic in the short-lived `offsite` container (egress network only, backup
#      folder mounted read-only; the key reaches it through compose's env_file, never an
#      argument): opens the repository, backs up the folder, then asks the repository for
#      the snapshot it just made. Only after that does it say ok.
# The sets are already age-encrypted (this host cannot decrypt them); restic encrypts the
# repository again with its own password. The storage key can add files but not delete them
# (and the bucket has Object Lock), so a thief on this host can add junk but cannot erase
# or rewrite history. The read-only steps run with --no-lock; `restic backup` always takes
# restic's own lock (it ignores --no-lock), and with this key removing that lock only hides
# the small file (the provider keeps the old version until the retention ends). While a
# backup holds it, a prune refuses to start. The monthly prune (runbook) runs from another
# machine with a different key, with the backup timer stopped.
#
# A failure here never touches the local sets or the database's record of the last good
# dump (backup.sh did both before this ran). It prints one line to stderr and exits non-zero,
# so the unit shows as failed: `systemctl --failed`, `journalctl -u soc-offsite.service`.
# The next run sends everything again (restic stores only what is new). Success prints one
# line: `offsite outcome=ok snapshot=<id> added_bytes=<n>`. restic's own output is not
# printed.
#
# Environment: SOC_STATE_DIR (default /srv/soc). SOC_INIT_TEST=1 is for tests only: it
# skips the root check, is refused for root, and is the only way to swap in SOC_COMPOSE.
set -euo pipefail

if [[ -n "${SOC_INIT_TEST:-}" && "$EUID" -eq 0 ]]; then
  echo "offsite outcome=failed step=start reason=SOC_INIT_TEST_refused_for_root" >&2
  exit 1
fi
if [[ -z "${SOC_INIT_TEST:-}" && "$EUID" -ne 0 ]]; then
  echo "offsite outcome=failed step=start reason=run_as_root" >&2
  exit 1
fi
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

HERE="$(cd "$(dirname "$0")" && pwd)"
STATE="${SOC_STATE_DIR:-/srv/soc}"
BACKUPS="$STATE/backups"
ENV_FILE="$STATE/env/offsite.env"

COMPOSE="$HERE/soc-compose.sh"
if [[ -n "${SOC_INIT_TEST:-}" ]]; then
  COMPOSE="${SOC_COMPOSE:-$COMPOSE}"
fi

STEP=start
fail() { echo "offsite outcome=failed step=$STEP reason=$1" >&2; exit 1; }

MODE=send
case "${1:-}" in
  --init)
    [[ $# -eq 1 ]] || fail "usage_offsite.sh_[--init]"
    MODE=init ;;
  "") ;;
  *) fail "usage_offsite.sh_[--init]" ;;
esac

# --- the key file ----------------------------------------------------------------------
STEP=config
[[ -f "$ENV_FILE" && ! -L "$ENV_FILE" && -s "$ENV_FILE" ]] || fail "missing_env/offsite.env_run_init-offsite.sh"
# any group or other permission at all (find -perm -077 would need ALL six bits; this form
# works the same on GNU and BSD find)
[[ -z "$(find "$ENV_FILE" -maxdepth 0 \( -perm -g+r -o -perm -g+w -o -perm -g+x \
  -o -perm -o+r -o -perm -o+w -o -perm -o+x \))" ]] || fail "env/offsite.env_is_readable_by_others"
# exactly these four, once each, each the right shape; nothing is echoed
REPO_RE='^s3:https://s3\.[a-z0-9-]+\.backblazeb2\.com/[A-Za-z0-9][A-Za-z0-9-]{4,48}(/[A-Za-z0-9._-]+)*$'
SEEN=""
LINES=0
while IFS= read -r line || [[ -n "$line" ]]; do
  LINES=$((LINES + 1))
  key="${line%%=*}"
  val="${line#*=}"
  [[ "$line" == *=* ]] || fail "env/offsite.env_has_a_line_this_does_not_understand"
  case "$key" in
    RESTIC_REPOSITORY) [[ "$val" =~ $REPO_RE ]] || fail "RESTIC_REPOSITORY_is_not_a_b2_s3_address" ;;
    RESTIC_PASSWORD) [[ "$val" =~ ^[0-9a-f]{32,128}$ ]] || fail "RESTIC_PASSWORD_is_not_32-128_hex_characters" ;;
    AWS_ACCESS_KEY_ID) [[ "$val" =~ ^[A-Za-z0-9]{10,40}$ ]] || fail "AWS_ACCESS_KEY_ID_has_the_wrong_shape" ;;
    AWS_SECRET_ACCESS_KEY) [[ "$val" =~ ^[A-Za-z0-9/+_-]{20,80}$ ]] || fail "AWS_SECRET_ACCESS_KEY_has_the_wrong_shape" ;;
    *) fail "env/offsite.env_has_a_line_this_does_not_understand" ;;
  esac
  case " $SEEN " in *" $key "*) fail "env/offsite.env_repeats_a_line" ;; esac
  SEEN="$SEEN $key"
done < "$ENV_FILE"
[[ "$LINES" == 4 ]] || fail "env/offsite.env_must_have_exactly_four_lines"

# --- something to send ---------------------------------------------------------------
STEP=set
COMPLETE=0
for sums in "$BACKUPS"/soc-*.sha256; do
  [[ -f "$sums" && ! -L "$sums" ]] || continue
  base="${sums%.sha256}"
  [[ -s "$base.dump.age" && -s "$base.globals.sql.age" ]] && COMPLETE=$((COMPLETE + 1))
done
if [[ "$MODE" == send && "$COMPLETE" -lt 1 ]]; then
  fail "no_complete_backup_set_to_send"
fi

# --- one at a time ----------------------------------------------------------------------
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
cleanup() {
  local rc=$?
  [[ -n "$TMP" ]] && rm -rf "$TMP"
  rm -rf "$LOCK"
  exit "$rc"
}
trap cleanup EXIT

rm -rf "$STATE"/.offsite.*
TMP="$(mktemp -d "$STATE/.offsite.XXXXXX")"
chmod 700 "$TMP"

# One restic command in the container. Nothing it prints is shown: it can name the bucket
# and the files, and a storage error can quote a request.
restic() { "$COMPOSE" run --rm -T --no-deps offsite "$@"; }

# --- the repository ---------------------------------------------------------------------
STEP=repository
EXISTS=0
restic cat config --no-lock --no-cache >/dev/null 2>&1 && EXISTS=1

if [[ "$MODE" == init ]]; then
  [[ "$EXISTS" == 0 ]] || fail "repository_already_exists_nothing_changed"
  STEP=init
  restic init --no-cache >/dev/null 2>&1 || fail "could_not_create_the_repository"
  echo "offsite outcome=ok init=created"
  exit 0
fi
[[ "$EXISTS" == 1 ]] || fail "cannot_open_the_repository_wrong_key_or_not_created_yet_offsite.sh_--init"

# --- send and check -----------------------------------------------------------------------
STEP=backup
RC=0
restic backup /backups --json --no-cache --host soc --tag soc-backup \
  --exclude '.lock' --exclude '.tmp.*' > "$TMP/backup.json" 2>/dev/null || RC=$?
(( RC == 0 )) || fail "restic_backup_failed_exit_$RC"
SNAP="$(grep -o '"snapshot_id":"[0-9a-f]\{8,64\}"' "$TMP/backup.json" | tail -n1 | cut -d'"' -f4 || true)"
[[ "$SNAP" =~ ^[0-9a-f]{8,64}$ ]] || fail "restic_reported_no_snapshot"
ADDED="$(grep -o '"data_added":[0-9]\{1,\}' "$TMP/backup.json" | tail -n1 | cut -d: -f2 || true)"
[[ "$ADDED" =~ ^[0-9]+$ ]] || ADDED=0

STEP=verify
restic snapshots --no-lock --no-cache --json "$SNAP" > "$TMP/snap.json" 2>/dev/null \
  || fail "the_repository_did_not_return_the_snapshot"
grep -Eq "\"(short_)?id\":\"$SNAP" "$TMP/snap.json" || fail "the_repository_did_not_return_the_snapshot"

echo "offsite outcome=ok snapshot=$SNAP added_bytes=$ADDED"
