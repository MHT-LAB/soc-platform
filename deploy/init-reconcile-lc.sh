#!/usr/bin/env bash
# Create the catch-up worker's vendor-API file. Run it once, as root, on the Stage A host
# after init-reconcile.sh. The API key is read from the keyboard with echo off (or, with
# --restore, from the environment), written straight to a mode-600 file and never printed:
# no person needs to see it again and no model ever does.
#
#   init-reconcile-lc.sh
#       asks for three things: the key (hidden), the organization id and the ingest
#       source's slug (the last two are not secret)
#   init-reconcile-lc.sh --restore
#       rebuild the file from SOC_LC_RECONCILE_KEY, SOC_LC_OID and SOC_INGEST_LC_SLUG in
#       the environment (from the secrets manager) after a lost host.
#
# It writes, in $SOC_STATE_DIR (default /srv/soc), mode 600:
#   env/reconcile-lc.env   SOC_RECONCILE_LC_KEY, SOC_RECONCILE_LC_OID, SOC_RECONCILE_SOURCE
# Create the key in the vendor's console as a read-only key (detection history only), name
# it for this service, and keep its own copy in the secrets manager. It never overwrites:
# if the file exists it stops before creating anything. The next `deploy.sh` starts the
# catch-up worker once this file and env/reconcile-db.env both exist.
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
LC_ENV="$ENV_DIR/reconcile-lc.env"

KEY_RE='^[A-Za-z0-9._-]{16,128}$'
OID_RE='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
SLUG_RE='^[a-z0-9-]{1,32}$'

die() { echo "FAILED: $*" >&2; exit 1; }

MODE=new
case "${1:-}" in
  --restore)
    [[ $# -eq 1 ]] || die "usage: init-reconcile-lc.sh [--restore]"
    MODE=restore ;;
  "") ;;
  *) die "usage: init-reconcile-lc.sh [--restore]" ;;
esac

if [[ "$MODE" == restore ]]; then
  LC_KEY="${SOC_LC_RECONCILE_KEY:-}"
  LC_OID="${SOC_LC_OID:-}"
  LC_SLUG="${SOC_INGEST_LC_SLUG:-}"
else
  # Prompts go to stderr; the key is read with echo off when this is a terminal.
  printf 'Vendor API key (read-only; hidden as you type): ' >&2
  IFS= read -rs LC_KEY || die "no key given"
  [[ -t 0 ]] && echo >&2
  printf 'Organization id: ' >&2
  IFS= read -r LC_OID || die "no organization id given"
  printf 'Ingest source slug (the lc-... part of the webhook address): ' >&2
  IFS= read -r LC_SLUG || die "no slug given"
fi
[[ "$LC_KEY" =~ $KEY_RE ]] || die "the key is missing or not 16-128 letters, digits, dots, dashes or underscores"
[[ "$LC_OID" =~ $OID_RE ]] || die "the organization id is missing or not a lower-case UUID"
[[ "$LC_SLUG" =~ $SLUG_RE ]] || die "the source slug is missing or malformed"

# --- refuse before creating anything ---------------------------------------------
[[ -s "$ENV_DIR/db-owner.env" ]] || die "$ENV_DIR/db-owner.env is missing: run init-secrets.sh first"
[[ -s "$ENV_DIR/reconcile-db.env" ]] || die "$ENV_DIR/reconcile-db.env is missing: run init-reconcile.sh first"
[[ ! -e "$LC_ENV" ]] || die "$LC_ENV already exists; this never overwrites"

# --- write -----------------------------------------------------------------------
umask 077
TMP="$(mktemp -d "$ENV_DIR/.init.XXXXXX")"
cleanup() {
  local rc=$?
  rm -rf "$TMP"
  exit "$rc"
}
trap cleanup EXIT

printf 'SOC_RECONCILE_LC_KEY=%s\nSOC_RECONCILE_LC_OID=%s\nSOC_RECONCILE_SOURCE=%s\n' \
  "$LC_KEY" "$LC_OID" "$LC_SLUG" > "$TMP/reconcile-lc.env"
[[ ! -e "$LC_ENV" ]] || die "$LC_ENV appeared while this ran; stopping"
mv "$TMP/reconcile-lc.env" "$LC_ENV"
chmod 600 "$LC_ENV"

# --- tell the operator what to keep, without any value ----------------------------
if [[ "$MODE" == restore ]]; then
  echo "restored $LC_ENV from the environment"
else
  printf '%s\n' \
    "Created $LC_ENV (mode 600). The key was not shown and is not stored anywhere else." \
    "" \
    "Keep the key itself in the secrets manager, folder /soc, as SOC_LC_RECONCILE_KEY," \
    "with SOC_LC_OID (the organization id; not secret). Then run deploy.sh."
fi
