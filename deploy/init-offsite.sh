#!/usr/bin/env bash
# Write the off-site copy's key file. Run it once, as root, on the Stage A host, after
# init-secrets.sh. The key and the repository address are made in the storage provider's
# console (runbook: docs/runbooks/database.md, "Off-site copy"); nothing here talks to it.
#
#   SOC_OFFSITE_REPOSITORY=s3:https://s3.<region>.backblazeb2.com/<bucket>[/<folder>] \
#   SOC_OFFSITE_KEY_ID=<application key id> \
#   init-offsite.sh
#       asks for the application key at the terminal (hidden) and makes a new repository
#       password. Prints the password once.
#   init-offsite.sh --restore
#       rebuilds the file after a lost host from SOC_OFFSITE_REPOSITORY, SOC_OFFSITE_KEY_ID,
#       SOC_OFFSITE_APP_KEY and SOC_OFFSITE_PASSWORD in the environment (from the secrets
#       manager); prints nothing secret.
#
# It writes, in $SOC_STATE_DIR (default /srv/soc), mode 600:
#   env/offsite.env    RESTIC_REPOSITORY, RESTIC_PASSWORD, AWS_ACCESS_KEY_ID,
#                      AWS_SECRET_ACCESS_KEY  (read by the `offsite` container only)
# The application key must be one that can add files but NOT delete them. The repository
# password is THE SECRET it prints: whoever has it and a read key can read every off-site
# copy (they are age-encrypted as well, so they still cannot open the data), and without it
# none can be read at all. Keep one copy in the secrets manager (folder /soc) and one on
# paper in the safe, with the age key. It never overwrites: if the file exists it stops
# before creating anything (a new password would make the repository unreadable).
#
# Environment: SOC_STATE_DIR. SOC_INIT_TEST=1 is for tests only: it skips the root check,
# reads the application key from standard input instead of the terminal, and is refused for
# root.
set -euo pipefail

if [[ -n "${SOC_INIT_TEST:-}" && "$EUID" -eq 0 ]]; then
  echo "FAILED: SOC_INIT_TEST is for tests only and is refused for root" >&2
  exit 1
fi
if [[ -z "${SOC_INIT_TEST:-}" && "$EUID" -ne 0 ]]; then
  echo "FAILED: run as root" >&2
  exit 1
fi
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

STATE="${SOC_STATE_DIR:-/srv/soc}"
ENV_DIR="$STATE/env"
OFFSITE_ENV="$ENV_DIR/offsite.env"

REPO_RE='^s3:https://s3\.[a-z0-9-]+\.backblazeb2\.com/[A-Za-z0-9][A-Za-z0-9-]{4,48}(/[A-Za-z0-9._-]+)*$'
KEY_ID_RE='^[A-Za-z0-9]{10,40}$'
APP_KEY_RE='^[A-Za-z0-9/+_-]{20,80}$'
PASSWORD_RE='^[0-9a-f]{32,128}$'

die() { echo "FAILED: $*" >&2; exit 1; }
rand_hex() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

MODE=new
case "${1:-}" in
  --restore)
    [[ $# -eq 1 ]] || die "usage: init-offsite.sh [--restore]"
    MODE=restore ;;
  "") ;;
  *) die "usage: init-offsite.sh [--restore]" ;;
esac

# --- refuse before creating anything ---------------------------------------------------
[[ -s "$ENV_DIR/db-owner.env" ]] || die "$ENV_DIR/db-owner.env is missing: run init-secrets.sh first"
[[ ! -e "$OFFSITE_ENV" ]] || die "$OFFSITE_ENV already exists; this never overwrites"

REPO="${SOC_OFFSITE_REPOSITORY:-}"
KEY_ID="${SOC_OFFSITE_KEY_ID:-}"
[[ "$REPO" =~ $REPO_RE ]] || die "SOC_OFFSITE_REPOSITORY is missing or is not s3:https://s3.<region>.backblazeb2.com/<bucket>[/<folder>]"
[[ "$KEY_ID" =~ $KEY_ID_RE ]] || die "SOC_OFFSITE_KEY_ID is missing or has the wrong shape"

APP_KEY=""
PASSWORD=""
if [[ "$MODE" == restore ]]; then
  APP_KEY="${SOC_OFFSITE_APP_KEY:-}"
  PASSWORD="${SOC_OFFSITE_PASSWORD:-}"
  [[ "$APP_KEY" =~ $APP_KEY_RE ]] || die "SOC_OFFSITE_APP_KEY is missing or has the wrong shape"
  [[ "$PASSWORD" =~ $PASSWORD_RE ]] || die "SOC_OFFSITE_PASSWORD is missing or not 32-128 hex characters"
else
  if [[ -n "${SOC_INIT_TEST:-}" ]]; then
    IFS= read -r APP_KEY || true
  else
    [[ -r /dev/tty ]] || die "no terminal to type the application key into"
    IFS= read -rs -p "B2 application key (typing is hidden): " APP_KEY < /dev/tty || true
    echo >&2
  fi
  [[ "$APP_KEY" =~ $APP_KEY_RE ]] || die "that is not an application key (wrong length or characters)"
  PASSWORD="$(rand_hex 32)"
fi

# --- write -----------------------------------------------------------------------------
umask 077
TMP="$(mktemp -d "$ENV_DIR/.init.XXXXXX")"
CREATED=""
cleanup() {
  local rc=$?
  APP_KEY=""
  rm -rf "$TMP"
  if [[ $rc -ne 0 && -n "$CREATED" ]]; then rm -f "$CREATED"; fi
  exit "$rc"
}
trap cleanup EXIT

# printf is a builtin: the values never become another program's argument.
printf '%s\n' \
  "RESTIC_REPOSITORY=$REPO" \
  "RESTIC_PASSWORD=$PASSWORD" \
  "AWS_ACCESS_KEY_ID=$KEY_ID" \
  "AWS_SECRET_ACCESS_KEY=$APP_KEY" > "$TMP/offsite.env"
[[ ! -e "$OFFSITE_ENV" ]] || die "$OFFSITE_ENV appeared while this ran; stopping"
mv "$TMP/offsite.env" "$OFFSITE_ENV"
CREATED="$OFFSITE_ENV"
chmod 600 "$OFFSITE_ENV"

# --- tell the operator -------------------------------------------------------------------
if [[ "$MODE" == restore ]]; then
  echo "restored $OFFSITE_ENV from the environment"
  exit 0
fi

printf '%s\n' \
  "Created $OFFSITE_ENV (mode 600)." \
  "" \
  "THE SECRET BELOW IS SHOWN ONCE. Do not paste it into chat, a ticket or a note." \
  "" \
  "Secrets manager, folder /soc (bulk import as .env)" \
  "SOC_OFFSITE_REPOSITORY=$REPO" \
  "SOC_OFFSITE_KEY_ID=$KEY_ID" \
  "SOC_OFFSITE_PASSWORD=$PASSWORD" \
  "(SOC_OFFSITE_APP_KEY is the key you just typed: store it from the provider's console.)" \
  "" \
  "Also write SOC_OFFSITE_PASSWORD on paper for the safe, beside the age key." \
  "When both are done, clear the terminal and its scrollback. Next: offsite.sh --init"
