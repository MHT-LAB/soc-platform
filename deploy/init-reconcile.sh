#!/usr/bin/env bash
# Create the catch-up worker's database secret files and print what must be stored
# elsewhere. Run it once, as root, on the Stage A host after init-secrets.sh. No person
# and no model needs to see a value: it is generated here and written straight to
# mode-600 files; the secrets-manager line is printed once, to the terminal.
#
#   init-reconcile.sh
#   init-reconcile.sh --restore
#       rebuild the files from one value in the environment (from the secrets
#       manager) after a lost host; prints nothing secret.
#
# It writes, in $SOC_STATE_DIR (default /srv/soc), both mode 600:
#   env/reconcile-db.env     SOC_RECONCILE_DATABASE_URL     (the catch-up worker)
#   env/reconcile-owner.env  SOC_RECONCILE_DB_PASSWORD      (migrate)
# The URL names the role soc_reconcile, which can only call ingest_alert() and the
# cursor functions. The key for the detection source's API is not made here: it is
# created in that vendor's console and stored separately. Nothing is written to
# deploy.log or anywhere else. It never overwrites: if either file exists it stops
# before creating anything. The next `deploy.sh` migration job gives the database role
# soc_reconcile its login from reconcile-owner.env.
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
RECONCILE_ENV="$ENV_DIR/reconcile-db.env"
OWNER_ENV="$ENV_DIR/reconcile-owner.env"

SECRET_RE='^[0-9a-f]{32,128}$'

die() { echo "FAILED: $*" >&2; exit 1; }
rand_hex() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

MODE=new
case "${1:-}" in
  --restore)
    [[ $# -eq 1 ]] || die "usage: init-reconcile.sh [--restore]"
    MODE=restore ;;
  "") ;;
  *) die "usage: init-reconcile.sh [--restore]" ;;
esac

if [[ "$MODE" == restore ]]; then
  RECONCILE_PW="${SOC_DB_RECONCILE_PASSWORD:-}"
  [[ "$RECONCILE_PW" =~ $SECRET_RE ]] || die "SOC_DB_RECONCILE_PASSWORD is missing or not 32-128 hex characters"
else
  RECONCILE_PW="$(rand_hex 24)"
fi

# --- refuse before creating anything ---------------------------------------------
[[ -s "$ENV_DIR/db-owner.env" ]] || die "$ENV_DIR/db-owner.env is missing: run init-secrets.sh first"
for f in "$RECONCILE_ENV" "$OWNER_ENV"; do
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

printf 'SOC_RECONCILE_DATABASE_URL=postgresql+psycopg://soc_reconcile:%s@db:5432/soc\n' \
  "$RECONCILE_PW" > "$TMP/reconcile-db.env"
printf 'SOC_RECONCILE_DB_PASSWORD=%s\n' "$RECONCILE_PW" > "$TMP/reconcile-owner.env"

install_file() { # name target
  [[ ! -e "$2" ]] || die "$2 appeared while this ran; stopping"
  mv "$TMP/$1" "$2"
  CREATED="$CREATED
$2"
  chmod 600 "$2"
}
install_file reconcile-db.env "$RECONCILE_ENV"
install_file reconcile-owner.env "$OWNER_ENV"

# --- tell the operator, once ----------------------------------------------------
if [[ "$MODE" == restore ]]; then
  echo "restored $RECONCILE_ENV and $OWNER_ENV from the environment"
  exit 0
fi

# printf is a shell builtin: the value never becomes another program's argument
# or passes through a here-document's temporary file.
printf '%s\n' \
  "Created $RECONCILE_ENV and $OWNER_ENV (mode 600)." \
  "" \
  "THE SECRET BELOW IS SHOWN ONCE. Do not paste it into chat, a ticket or a note." \
  "" \
  "Secrets manager, folder /soc (bulk import as .env)" \
  "SOC_DB_RECONCILE_PASSWORD=$RECONCILE_PW" \
  "" \
  "When it is saved, clear the terminal and its scrollback, then run deploy.sh."
