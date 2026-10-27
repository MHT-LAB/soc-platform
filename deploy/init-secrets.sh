#!/usr/bin/env bash
# Create the host's secret files (database and ingest) and print what must be
# stored elsewhere. Run it once, as root, on the Stage A host. No person and no
# model needs to see a value: they are generated here and written straight to
# mode-600 files.
#
#   init-secrets.sh <source-name> <public-host>
#       e.g. init-secrets.sh lc-0123456789abcdef soc.example.com
#   init-secrets.sh --restore
#       rebuild the files from five values in the environment (from the secrets
#       manager) after a lost host; prints nothing secret.
#
# <source-name> is `lc-` plus 16 random lowercase letters and digits. It is not a
# credential, it only keeps strangers from finding the endpoint, so make it
# unguessable (see docs/runbooks/deploy.md).
#
# It writes, in $SOC_STATE_DIR (default /srv/soc):
#   env/db.env         POSTGRES_PASSWORD, SOC_DB_OWNER_PASSWORD         (db)
#   env/db-owner.env   SOC_MIGRATE_URL, SOC_INGEST_DB_PASSWORD          (migrate)
#   env/ingest.env     SOC_INGEST_SECRETS, SOC_INGEST_DATABASE_URL      (api)
#   pgdata/            empty, owned by uid 999, mode 700
#   seed/              empty
# and prints, once, to the terminal only: the webhook destination and key for the
# EDR output, and a block of NAME=value lines for the secrets manager's folder
# /soc. Nothing is written to deploy.log or anywhere else. It never overwrites:
# if any target already exists it stops before creating anything.
#
# Environment: SOC_STATE_DIR. SOC_INIT_TEST=1 is for tests only: it skips the root
# check and the chown, and is refused for root.
set -euo pipefail

# $EUID is a bash builtin, so no fake "id" can lie about it.
if [[ -n "${SOC_INIT_TEST:-}" && "$EUID" -eq 0 ]]; then
  echo "FAILED: SOC_INIT_TEST is for tests only and is refused for root" >&2
  exit 1
fi
if [[ -z "${SOC_INIT_TEST:-}" && "$EUID" -ne 0 ]]; then
  echo "FAILED: run as root (the data directory belongs to uid 999)" >&2
  exit 1
fi
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

STATE="${SOC_STATE_DIR:-/srv/soc}"
ENV_DIR="$STATE/env"
DB_ENV="$ENV_DIR/db.env"
OWNER_ENV="$ENV_DIR/db-owner.env"
INGEST_ENV="$ENV_DIR/ingest.env"
PGDATA_DIR="$STATE/pgdata"
SEED_DIR="$STATE/seed"

SLUG_RE='^lc-[a-z0-9]{16}$'
HOST_RE='^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$'
SECRET_RE='^[0-9a-f]{32,128}$'

die() { echo "FAILED: $*" >&2; exit 1; }
rand_hex() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

MODE=new
case "${1:-}" in
  --restore)
    [[ $# -eq 1 ]] || die "usage: init-secrets.sh --restore"
    MODE=restore ;;
  "" | -*)
    die "usage: init-secrets.sh <source-name> <public-host> | --restore" ;;
  *)
    [[ $# -eq 2 ]] || die "usage: init-secrets.sh <source-name> <public-host>"
    SLUG="$1"
    HOST="$2"
    [[ "$SLUG" =~ $SLUG_RE ]] || die "the source name must be lc- plus 16 lowercase letters or digits"
    [[ "$HOST" =~ $HOST_RE && "$HOST" == *.* ]] || die "the public host must be a lowercase host name such as soc.example.com" ;;
esac

if [[ "$MODE" == restore ]]; then
  SLUG="${SOC_INGEST_LC_SLUG:-}"
  SUPER_PW="${SOC_DB_SUPERUSER_PASSWORD:-}"
  OWNER_PW="${SOC_DB_OWNER_PASSWORD:-}"
  INGEST_PW="${SOC_DB_INGEST_PASSWORD:-}"
  HMAC="${SOC_INGEST_LC_HMAC:-}"
  [[ "$SLUG" =~ $SLUG_RE ]] || die "SOC_INGEST_LC_SLUG is missing or malformed"
  for name in SUPER_PW OWNER_PW INGEST_PW HMAC; do
    [[ "${!name}" =~ $SECRET_RE ]] || die "the value for $name is missing or not 32-128 hex characters"
  done
else
  SUPER_PW="$(rand_hex 24)"
  OWNER_PW="$(rand_hex 24)"
  INGEST_PW="$(rand_hex 24)"
  HMAC="$(rand_hex 32)"
fi

# --- refuse before creating anything ---------------------------------------------
for f in "$DB_ENV" "$OWNER_ENV" "$INGEST_ENV"; do
  [[ ! -e "$f" ]] || die "$f already exists; this never overwrites"
done
if [[ "$MODE" == new && -e "$PGDATA_DIR" ]]; then
  [[ -d "$PGDATA_DIR" && -z "$(ls -A "$PGDATA_DIR")" ]] \
    || die "$PGDATA_DIR already holds data; new secrets would not match it (use --restore)"
fi

# --- write -----------------------------------------------------------------------
umask 077
mkdir -p "$ENV_DIR"
chmod 700 "$ENV_DIR"
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

printf 'POSTGRES_PASSWORD=%s\nSOC_DB_OWNER_PASSWORD=%s\n' "$SUPER_PW" "$OWNER_PW" > "$TMP/db.env"
printf 'SOC_MIGRATE_URL=postgresql+psycopg://soc_owner:%s@db:5432/soc\nSOC_INGEST_DB_PASSWORD=%s\n' \
  "$OWNER_PW" "$INGEST_PW" > "$TMP/db-owner.env"
printf 'SOC_INGEST_SECRETS={"%s":["%s"]}\nSOC_INGEST_DATABASE_URL=postgresql+psycopg://soc_ingest:%s@db:5432/soc\n' \
  "$SLUG" "$HMAC" "$INGEST_PW" > "$TMP/ingest.env"

install_file() { # name target
  [[ ! -e "$2" ]] || die "$2 appeared while this ran; stopping"
  mv "$TMP/$1" "$2"
  CREATED="$CREATED
$2"
  chmod 600 "$2"
}
install_file db.env "$DB_ENV"
install_file db-owner.env "$OWNER_ENV"
install_file ingest.env "$INGEST_ENV"

mkdir -p "$PGDATA_DIR" "$SEED_DIR"
chmod 700 "$PGDATA_DIR"
chmod 755 "$SEED_DIR"
if [[ -z "${SOC_INIT_TEST:-}" ]]; then
  chown 999:999 "$PGDATA_DIR"
fi

# --- tell the operator, once ----------------------------------------------------
if [[ "$MODE" == restore ]]; then
  echo "restored $DB_ENV, $OWNER_ENV and $INGEST_ENV from the environment"
  exit 0
fi

# printf is a shell builtin: the values never become another program's arguments
# or pass through a here-document's temporary file.
printf '%s\n' \
  "Created $DB_ENV, $OWNER_ENV and $INGEST_ENV (mode 600), $PGDATA_DIR and $SEED_DIR." \
  "" \
  "SECRETS BELOW ARE SHOWN ONCE. Do not paste them into chat, a ticket or a note." \
  "" \
  "1) EDR webhook output" \
  "   Destination Host: https://$HOST/ingest/$SLUG" \
  "   secret_key:       $HMAC" \
  "" \
  "2) Secrets manager, folder /soc (bulk import as .env)" \
  "SOC_DB_SUPERUSER_PASSWORD=$SUPER_PW" \
  "SOC_DB_OWNER_PASSWORD=$OWNER_PW" \
  "SOC_DB_INGEST_PASSWORD=$INGEST_PW" \
  "SOC_INGEST_LC_SLUG=$SLUG" \
  "SOC_INGEST_LC_HMAC=$HMAC" \
  "" \
  "When both are saved, clear the terminal and its scrollback."
