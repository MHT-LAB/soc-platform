#!/usr/bin/env bash
# Create the rules deploy's settings file. Run it once, as root, on the Stage A host. The two
# keys are read from the keyboard with echo off (or, with --restore, from the environment),
# written straight to a mode-600 file and never printed: no person needs to see them again
# and no model ever does.
#
#   init-rules-lc.sh
#       asks for: the vendor key (hidden), the organization id, the stamp key (hidden), the
#       organization's folder name in the rules repository, and the managed name prefixes
#   init-rules-lc.sh --restore
#       rebuild the file from SOC_LC_RULES_DEPLOY_KEY, SOC_LC_OID, SOC_RULES_STAMP_KEY,
#       SOC_RULES_ORG and SOC_RULES_PREFIXES in the environment (from the secrets manager)
#       after a lost host.
#
# It writes, in $SOC_STATE_DIR (default /srv/soc), mode 600:
#   env/rules-lc.env   SOC_RULES_LC_KEY, SOC_RULES_LC_OID, SOC_RULES_STAMP_KEY,
#                      SOC_RULES_ORG, SOC_RULES_PREFIXES
# Create the vendor key in the vendor's console as `soc-rules-deploy` with exactly dr.list,
# dr.set, dr.del (never output.*, sensor writes, org.* or billing). Only the one-shot `rules`
# service reads this file; no long-running service ever gets it. It never overwrites: if the
# file exists it stops before creating anything.
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
RULES_ENV="$ENV_DIR/rules-lc.env"

KEY_RE='^[A-Za-z0-9._-]{16,128}$'
# The stamp key goes through a compose env file: letters, digits, dot, dash and underscore only,
# so nothing in it can be read as a quote, a comment or a variable.
STAMP_RE='^[A-Za-z0-9._-]{32,255}$'
OID_RE='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
ORG_RE='^[a-z0-9-]{1,32}$'
# Prefixes are separated by "|"; each is 3-64 of letters, digits, space, dot, dash, underscore.
PREFIXES_RE='^[A-Za-z0-9 ._-]{3,64}(\|[A-Za-z0-9 ._-]{3,64})*$'

die() { echo "FAILED: $*" >&2; exit 1; }

MODE=new
case "${1:-}" in
  --restore)
    [[ $# -eq 1 ]] || die "usage: init-rules-lc.sh [--restore]"
    MODE=restore ;;
  "") ;;
  *) die "usage: init-rules-lc.sh [--restore]" ;;
esac

if [[ "$MODE" == restore ]]; then
  LC_KEY="${SOC_LC_RULES_DEPLOY_KEY:-}"
  LC_OID="${SOC_LC_OID:-}"
  STAMP_KEY="${SOC_RULES_STAMP_KEY:-}"
  ORG="${SOC_RULES_ORG:-}"
  PREFIXES="${SOC_RULES_PREFIXES:-}"
else
  # Prompts go to stderr; the keys are read with echo off when this is a terminal.
  printf 'Vendor API key for rules (dr.list, dr.set, dr.del only; hidden as you type): ' >&2
  IFS= read -rs LC_KEY || die "no key given"
  [[ -t 0 ]] && echo >&2
  printf 'Organization id: ' >&2
  IFS= read -r LC_OID || die "no organization id given"
  printf 'Stamp key (32+ letters, digits, dot, dash, underscore; hidden as you type): ' >&2
  IFS= read -rs STAMP_KEY || die "no stamp key given"
  [[ -t 0 ]] && echo >&2
  printf "The organization's folder name in the rules repository (orgs/<name>): " >&2
  IFS= read -r ORG || die "no folder name given"
  printf 'Managed name prefixes, separated by | (a trailing space counts): ' >&2
  IFS= read -r PREFIXES || die "no prefixes given"
fi
[[ "$LC_KEY" =~ $KEY_RE ]] || die "the vendor key is missing or not 16-128 letters, digits, dots, dashes or underscores"
[[ "$LC_OID" =~ $OID_RE ]] || die "the organization id is missing or not a lower-case UUID"
[[ "$STAMP_KEY" =~ $STAMP_RE ]] || die "the stamp key is missing or not 32-255 letters, digits, dots, dashes or underscores"
[[ "$ORG" =~ $ORG_RE ]] || die "the folder name is missing or not 1-32 lower-case letters, digits or dashes"
[[ "$PREFIXES" =~ $PREFIXES_RE ]] || die "the prefixes are missing or malformed (3-64 letters, digits, spaces, dots, dashes or underscores each, separated by |)"
[[ "$LC_KEY" != "$STAMP_KEY" ]] || die "the stamp key must not be the vendor key"

# --- refuse before creating anything ---------------------------------------------
[[ -d "$ENV_DIR" ]] || die "$ENV_DIR is missing: run init-secrets.sh first"
[[ ! -e "$RULES_ENV" ]] || die "$RULES_ENV already exists; this never overwrites"

# --- write -----------------------------------------------------------------------
umask 077
TMP="$(mktemp -d "$ENV_DIR/.init.XXXXXX")"
cleanup() {
  local rc=$?
  rm -rf "$TMP"
  exit "$rc"
}
trap cleanup EXIT

# The prefixes are quoted: a compose env file would drop a trailing space otherwise.
printf 'SOC_RULES_LC_KEY=%s\nSOC_RULES_LC_OID=%s\nSOC_RULES_STAMP_KEY=%s\nSOC_RULES_ORG=%s\nSOC_RULES_PREFIXES="%s"\n' \
  "$LC_KEY" "$LC_OID" "$STAMP_KEY" "$ORG" "$PREFIXES" > "$TMP/rules-lc.env"
[[ ! -e "$RULES_ENV" ]] || die "$RULES_ENV appeared while this ran; stopping"
mv "$TMP/rules-lc.env" "$RULES_ENV"
chmod 600 "$RULES_ENV"

# --- tell the operator what to keep, without any value ----------------------------
if [[ "$MODE" == restore ]]; then
  echo "restored $RULES_ENV from the environment"
else
  printf '%s\n' \
    "Created $RULES_ENV (mode 600). The keys were not shown and are not stored anywhere else." \
    "" \
    "Keep the vendor key in the secrets manager, folder /soc, as SOC_LC_RULES_DEPLOY_KEY," \
    "the stamp key as SOC_RULES_STAMP_KEY (the posture collector gets the same one), and the" \
    "organization id as SOC_LC_OID (not secret). Rotation: the vendor key every 90 days." \
    "Then run rules-deploy.sh."
fi
