#!/usr/bin/env bash
# Create the backup key pair. Run it once, as root, on the Stage A host. The host keeps only
# the PUBLIC half (it can encrypt backups, never read them); the private half is printed once,
# to the terminal, and is never written to any file on the host.
#
#   init-backup.sh
#   init-backup.sh --restore
#       rebuild env/backup-age.pub from SOC_BACKUP_AGE_PUB in the environment (from the
#       secrets manager) after a lost host; prints nothing secret.
#
# It writes, in $SOC_STATE_DIR (default /srv/soc), mode 600:
#   env/backup-age.pub    the age public key (one line; not secret)
# and prints, once:
#   SOC_BACKUP_AGE_PUB=...   (not secret; keep it beside the other one)
#   SOC_BACKUP_AGE_KEY=...   (THE SECRET: secrets manager folder /soc, and on paper)
# Whoever holds the private key can read every backup, and without it none can be read: keep
# one copy in the secrets manager and one on paper in the safe. It never overwrites: if the
# public key file exists it stops before creating anything (a second key would make the older
# backups unreadable by the new one). Needs the `age` package (apt install age).
#
# Environment: SOC_STATE_DIR. SOC_INIT_TEST=1 is for tests only: it skips the root check and
# is refused for root.
set -euo pipefail

if [[ -n "${SOC_INIT_TEST:-}" && "$EUID" -eq 0 ]]; then
  echo "FAILED: SOC_INIT_TEST is for tests only and is refused for root" >&2
  exit 1
fi
if [[ -z "${SOC_INIT_TEST:-}" && "$EUID" -ne 0 ]]; then
  echo "FAILED: run as root" >&2
  exit 1
fi
if [[ -n "${SOC_INIT_TEST:-}" && -n "${SOC_TEST_PATH:-}" ]]; then
  export PATH="$SOC_TEST_PATH"
else
  export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
fi

STATE="${SOC_STATE_DIR:-/srv/soc}"
ENV_DIR="$STATE/env"
PUB_FILE="$ENV_DIR/backup-age.pub"

PUB_RE='^age1[0-9a-z]{50,}$'
KEY_RE='^AGE-SECRET-KEY-1[0-9A-Z]{50,}$'

die() { echo "FAILED: $*" >&2; exit 1; }

MODE=new
case "${1:-}" in
  --restore)
    [[ $# -eq 1 ]] || die "usage: init-backup.sh [--restore]"
    MODE=restore ;;
  "") ;;
  *) die "usage: init-backup.sh [--restore]" ;;
esac

# --- refuse before creating anything ---------------------------------------------------
[[ -s "$ENV_DIR/db-owner.env" ]] || die "$ENV_DIR/db-owner.env is missing: run init-secrets.sh first"
[[ ! -e "$PUB_FILE" ]] || die "$PUB_FILE already exists; this never overwrites"

SECRET=""
if [[ "$MODE" == restore ]]; then
  PUB="${SOC_BACKUP_AGE_PUB:-}"
  [[ "$PUB" =~ $PUB_RE ]] || die "SOC_BACKUP_AGE_PUB is missing or is not an age public key"
else
  command -v age-keygen >/dev/null 2>&1 || die "age is not installed: apt install age"
  PAIR="$(age-keygen 2>/dev/null)" || die "age-keygen failed"
  SECRET="$(printf '%s\n' "$PAIR" | grep -E '^AGE-SECRET-KEY-' | head -n1 || true)"
  [[ "$SECRET" =~ $KEY_RE ]] || die "age-keygen printed no private key"
  PUB="$(printf '%s\n' "$SECRET" | age-keygen -y 2>/dev/null)" || die "age-keygen -y failed"
  [[ "$PUB" =~ $PUB_RE ]] || die "age-keygen printed no public key"
  PAIR=""
fi

# --- write (the public key only) -------------------------------------------------------
umask 077
TMP="$(mktemp -d "$ENV_DIR/.init.XXXXXX")"
CREATED=""
cleanup() {
  local rc=$?
  rm -rf "$TMP"
  if [[ $rc -ne 0 && -n "$CREATED" ]]; then rm -f "$CREATED"; fi
  exit "$rc"
}
trap cleanup EXIT

printf '%s\n' "$PUB" > "$TMP/backup-age.pub"
[[ ! -e "$PUB_FILE" ]] || die "$PUB_FILE appeared while this ran; stopping"
mv "$TMP/backup-age.pub" "$PUB_FILE"
CREATED="$PUB_FILE"
chmod 600 "$PUB_FILE"

# --- tell the operator, once -----------------------------------------------------------
if [[ "$MODE" == restore ]]; then
  echo "restored $PUB_FILE from the environment"
  exit 0
fi

# printf is a shell builtin: the value never becomes another program's argument or passes
# through a here-document's temporary file.
printf '%s\n' \
  "Created $PUB_FILE (mode 600). The private key was not written to any file." \
  "" \
  "THE SECRET BELOW IS SHOWN ONCE. Do not paste it into chat, a ticket or a note." \
  "" \
  "Secrets manager, folder /soc (bulk import as .env)" \
  "SOC_BACKUP_AGE_PUB=$PUB" \
  "SOC_BACKUP_AGE_KEY=$SECRET" \
  "" \
  "Also write SOC_BACKUP_AGE_KEY on paper for the safe (the whole line, starting AGE-SECRET-KEY-1)." \
  "When both are done, clear the terminal and its scrollback, then enable the timer."
