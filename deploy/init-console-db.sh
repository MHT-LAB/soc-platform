#!/usr/bin/env bash
# Create the console's secret files for the case pages and print what must be stored
# elsewhere. Run it once, as root, on the Stage A host after init-secrets.sh. No person
# and no model needs to see a value: they are generated here and written straight to
# mode-600 files; the secrets-manager block is printed once, to the terminal.
#
#   init-console-db.sh
#   init-console-db.sh --restore
#       rebuild the files from two values in the environment (from the secrets
#       manager) after a lost host; prints nothing secret.
#
# It writes, in $SOC_STATE_DIR (default /srv/soc), both mode 600:
#   env/console-db.env     SOC_CONSOLE_DATABASE_URL, SOC_CONSOLE_SECRET  (console)
#   env/console-owner.env  SOC_CONSOLE_DB_PASSWORD                       (migrate)
# SOC_CONSOLE_DATABASE_URL points at 127.0.0.1:5432: the console runs on the host
# network and the database publishes that port on the host's loopback only.
# SOC_CONSOLE_SECRET signs the form tokens that stop another web page from pressing
# Acknowledge or Close for you. Nothing is written to deploy.log or anywhere else. It
# never overwrites: if either file exists it stops before creating anything. The next
# `deploy.sh` migration job gives the database role soc_console its login from
# console-owner.env, and the console reads console-db.env.
#
# Environment: SOC_STATE_DIR. SOC_INIT_TEST=1 is for tests only: it skips the root
# check and is refused for root.
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
CONSOLE_ENV="$ENV_DIR/console-db.env"
OWNER_ENV="$ENV_DIR/console-owner.env"

SECRET_RE='^[0-9a-f]{32,128}$'

die() { echo "FAILED: $*" >&2; exit 1; }
rand_hex() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

MODE=new
case "${1:-}" in
  --restore)
    [[ $# -eq 1 ]] || die "usage: init-console-db.sh [--restore]"
    MODE=restore ;;
  "") ;;
  *) die "usage: init-console-db.sh [--restore]" ;;
esac

if [[ "$MODE" == restore ]]; then
  CONSOLE_PW="${SOC_DB_CONSOLE_PASSWORD:-}"
  FORM_KEY="${SOC_CONSOLE_SECRET:-}"
  [[ "$CONSOLE_PW" =~ $SECRET_RE ]] || die "SOC_DB_CONSOLE_PASSWORD is missing or not 32-128 hex characters"
  [[ "$FORM_KEY" =~ $SECRET_RE ]] || die "SOC_CONSOLE_SECRET is missing or not 32-128 hex characters"
else
  CONSOLE_PW="$(rand_hex 24)"
  FORM_KEY="$(rand_hex 32)"
fi

# --- refuse before creating anything ---------------------------------------------
[[ -s "$ENV_DIR/db-owner.env" ]] || die "$ENV_DIR/db-owner.env is missing: run init-secrets.sh first"
for f in "$CONSOLE_ENV" "$OWNER_ENV"; do
  [[ ! -e "$f" ]] || die "$f already exists; this never overwrites"
done

# --- write -----------------------------------------------------------------------
umask 077
TMP="$(mktemp -d "$ENV_DIR/.init.XXXXXX")"
CREATED=""
cleanup() {
  local rc=$?
  rm -rf "$TMP"
  if [[ $rc -ne 0 && -n "$CREATED" ]]; then
    while IFS= read -r f; do [[ -n "$f" ]] && rm -f "$f"; done <<< "$CREATED"
  fi
  exit "$rc"
}
trap cleanup EXIT

printf 'SOC_CONSOLE_DATABASE_URL=postgresql+psycopg://soc_console:%s@127.0.0.1:5432/soc\nSOC_CONSOLE_SECRET=%s\n' \
  "$CONSOLE_PW" "$FORM_KEY" > "$TMP/console-db.env"
printf 'SOC_CONSOLE_DB_PASSWORD=%s\n' "$CONSOLE_PW" > "$TMP/console-owner.env"

install_file() { # name target
  [[ ! -e "$2" ]] || die "$2 appeared while this ran; stopping"
  mv "$TMP/$1" "$2"
  CREATED="$CREATED
$2"
  chmod 600 "$2"
}
install_file console-db.env "$CONSOLE_ENV"
install_file console-owner.env "$OWNER_ENV"

# --- tell the operator, once ----------------------------------------------------
if [[ "$MODE" == restore ]]; then
  echo "restored $CONSOLE_ENV and $OWNER_ENV from the environment"
  exit 0
fi

# printf is a shell builtin: the values never become another program's arguments
# or pass through a here-document's temporary file.
printf '%s\n' \
  "Created $CONSOLE_ENV and $OWNER_ENV (mode 600)." \
  "" \
  "SECRETS BELOW ARE SHOWN ONCE. Do not paste them into chat, a ticket or a note." \
  "" \
  "Secrets manager, folder /soc (bulk import as .env)" \
  "SOC_DB_CONSOLE_PASSWORD=$CONSOLE_PW" \
  "SOC_CONSOLE_SECRET=$FORM_KEY" \
  "" \
  "When both are saved, clear the terminal and its scrollback, then run deploy.sh."
