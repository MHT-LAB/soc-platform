#!/usr/bin/env bash
# Create the pager worker's secret files and print what must be stored elsewhere.
# Run it once, as root, on the Stage A host after init-secrets.sh. No person and no
# model needs to see a value except the phone's topic, which only you can type into
# the phone: it is printed once, to the terminal.
#
#   init-worker.sh
#   init-worker.sh --restore
#       rebuild the files from two values in the environment (from the secrets
#       manager) after a lost host; prints nothing secret.
#
# It writes, in $SOC_STATE_DIR (default /srv/soc), both mode 600:
#   env/worker.env        SOC_NTFY_TOPIC, SOC_WORKER_DATABASE_URL     (worker)
#   env/worker-owner.env  SOC_WORKER_DB_PASSWORD                      (migrate)
# and prints, once, to the terminal only: the topic to subscribe the phone to and a
# block of NAME=value lines for the secrets manager's folder /soc. Nothing is written
# to deploy.log or anywhere else. It never overwrites: if either file exists it stops
# before creating anything. The next `deploy.sh` migration job gives the database role
# soc_worker its login from worker-owner.env, and deploy.sh starts the worker once
# worker.env exists.
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
WORKER_ENV="$ENV_DIR/worker.env"
OWNER_ENV="$ENV_DIR/worker-owner.env"

TOPIC_RE='^[A-Za-z0-9_-]{16,64}$'
SECRET_RE='^[0-9a-f]{32,128}$'

die() { echo "FAILED: $*" >&2; exit 1; }
rand_hex() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

MODE=new
case "${1:-}" in
  --restore)
    [[ $# -eq 1 ]] || die "usage: init-worker.sh [--restore]"
    MODE=restore ;;
  "") ;;
  *) die "usage: init-worker.sh [--restore]" ;;
esac

if [[ "$MODE" == restore ]]; then
  TOPIC="${SOC_NTFY_TOPIC:-}"
  WORKER_PW="${SOC_DB_WORKER_PASSWORD:-}"
  [[ "$TOPIC" =~ $TOPIC_RE ]] || die "SOC_NTFY_TOPIC is missing or malformed"
  [[ "$WORKER_PW" =~ $SECRET_RE ]] || die "SOC_DB_WORKER_PASSWORD is missing or not 32-128 hex characters"
else
  TOPIC="sec-$(rand_hex 16)"
  WORKER_PW="$(rand_hex 24)"
fi

# --- refuse before creating anything ---------------------------------------------
[[ -s "$ENV_DIR/db-owner.env" ]] || die "$ENV_DIR/db-owner.env is missing: run init-secrets.sh first"
for f in "$WORKER_ENV" "$OWNER_ENV"; do
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

printf 'SOC_NTFY_TOPIC=%s\nSOC_WORKER_DATABASE_URL=postgresql+psycopg://soc_worker:%s@db:5432/soc\n' \
  "$TOPIC" "$WORKER_PW" > "$TMP/worker.env"
printf 'SOC_WORKER_DB_PASSWORD=%s\n' "$WORKER_PW" > "$TMP/worker-owner.env"

install_file() { # name target
  [[ ! -e "$2" ]] || die "$2 appeared while this ran; stopping"
  mv "$TMP/$1" "$2"
  CREATED="$CREATED
$2"
  chmod 600 "$2"
}
install_file worker.env "$WORKER_ENV"
install_file worker-owner.env "$OWNER_ENV"

# --- tell the operator, once ----------------------------------------------------
if [[ "$MODE" == restore ]]; then
  echo "restored $WORKER_ENV and $OWNER_ENV from the environment"
  exit 0
fi

# printf is a shell builtin: the values never become another program's arguments
# or pass through a here-document's temporary file.
printf '%s\n' \
  "Created $WORKER_ENV and $OWNER_ENV (mode 600)." \
  "" \
  "SECRETS BELOW ARE SHOWN ONCE. Do not paste them into chat, a ticket or a note." \
  "" \
  "1) Phone: in the ntfy app, subscribe to this topic on the default server (ntfy.sh)" \
  "   Topic: $TOPIC" \
  "" \
  "2) Secrets manager, folder /soc (bulk import as .env)" \
  "SOC_NTFY_TOPIC=$TOPIC" \
  "SOC_DB_WORKER_PASSWORD=$WORKER_PW" \
  "" \
  "When both are saved, clear the terminal and its scrollback, then run deploy.sh."
