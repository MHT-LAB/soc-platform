#!/usr/bin/env bash
# Plan, record and apply key rotations. Run it as root on the host.
#
#   rotate.sh                     the plan, then a typed yes to approve it
#   rotate.sh --plan [--quiet]    the plan only, nothing asked (the daily timer runs this)
#   rotate.sh --record <id> [<id> ...] [--date YYYY-MM-DD] [--due YYYY-MM-DD]
#                                 keys were rotated by hand: write them down (one typed yes)
#   rotate.sh --preflight         the read calls of an apply (logins, the vendor's key list,
#                                 the stored value's name); changes nothing
#   rotate.sh --apply <plan-hash> rotate the automatic keys of the plan that was approved
#
# The first three only plan and record: they run in a container with no network. The approve and
# --record modes ask for a typed yes, so they refuse at once without a terminal (run them from
# `pct enter`, not `pct exec`); --plan (the timer), --preflight and --apply never need one.
# --preflight and --apply run as standard-library Python on this host (they must rewrite a consumer's env
# file, recreate its service and run its check, which a hardened container cannot do without
# the Docker socket). They read their rights (the vendor key that makes keys, the login to the
# secrets manager) from STANDARD INPUT ONLY: `NAME=value` lines, then a blank line, piped in
# from the operator's own machine. This script never reads stdin (every command but the last
# gets /dev/null), never puts a right in the environment or on a command line, and the Python
# it starts has an empty environment.
#
# 1. Bring the key register clone (default /opt/key-register) up to origin/main (fast-forward
#    only, over its own read-only deploy key), then require: a clean tree, a head commit exactly
#    at origin/main, and a head commit whose signature verifies (git reports status G).
#    Anything else is refused before anything is run.
# 2. Check the host has been deployed (env/image.env). The service needs no settings file: it
#    holds no key, has no network and cannot reach a vendor.
# 3. Run the one-shot `rotate` service (python -m soc_api.rotate), or for --preflight and
#    --apply the same module on the host. deploy.sh never starts it; only this script does.
# 4. Append the record lines to rotate.log and print them, for the vault Build Log.
#    The exit code is the service's: 0 done or nothing due, 1 could not write its files,
#    2 refused before changing anything, 3 not confirmed, 4 (plan only) something is overdue,
#    has no record, or has an old key still live.
#
# Environment (defaults suit the Stage A container):
#   SOC_STATE_DIR      state root                                    /srv/soc
#   SOC_KEYS_REPO      the key register clone                        /opt/key-register
#   SOC_KEYS_SSH_KEY   the clone's read-only deploy key, if git does not already know it
#   SOC_TEST_BIN       TESTS ONLY: directory searched first for docker. Refused for root, so
#                      nothing in the environment can swap a tool on a host. In this mode the
#                      terminal check is skipped unless SOC_TEST_ENFORCE_TTY is also set.
set -euo pipefail

if [[ -n "${SOC_TEST_BIN:-}" && "$EUID" -eq 0 ]]; then
  echo "FAILED: SOC_TEST_BIN is for tests only and is refused for root" >&2
  exit 1
fi
if [[ "$EUID" -ne 0 && -z "${SOC_TEST_BIN:-}" ]]; then
  echo "FAILED: run as root" >&2
  exit 1
fi
# Standard input may carry the rights (--preflight, --apply). Save it on descriptor 3 and give
# every command in between /dev/null instead, so nothing (git, ssh, gpg, a hook) can read it.
# Only the final run below is handed descriptor 3 back, as its stdin.
exec 3<&0 0</dev/null
# Don't depend on how the shell was opened (pct enter gives a minimal PATH).
export PATH="${SOC_TEST_BIN:+$SOC_TEST_BIN:}/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
# Never let the shell choose profiles or the commit: both come from this script.
unset COMPOSE_PROFILES SOC_ROTATE_COMMIT SOC_KEYS_SRC
export SOC_ENV=prod

STATE="${SOC_STATE_DIR:-/srv/soc}"
REPO="${SOC_KEYS_REPO:-/opt/key-register}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$STATE/rotate"
LOG="$STATE/rotate.log"

usage() {
  echo "usage: rotate.sh [--plan [--quiet] | --record <id> [<id> ...] [--date YYYY-MM-DD] [--due YYYY-MM-DD] | --preflight | --apply <plan-hash>]" >&2
  exit 2
}

# The arguments are checked here, in the shell, before anything else happens. The service
# checks them again: the second check is the one that counts, this one keeps junk off the
# command line.
ID_RE='^[a-z0-9][a-z0-9-]{1,48}$'
DAY_RE='^[0-9]{4}-[0-9]{2}-[0-9]{2}$'
HASH_RE='^[0-9a-f]{12}$'
MAX_IDS=20 # one record line each, and the record keeps 20 lines
ARGS=()
RUN_FLAGS=(--rm)
HOST_MODE=""
NEEDS_TTY=""
if [[ $# -eq 0 ]]; then
  NEEDS_TTY=1 # the plan, then a typed yes
else
  case "$1" in
    --plan)
      ARGS+=(--plan)
      shift
      if [[ "${1:-}" == "--quiet" ]]; then ARGS+=(--quiet); shift; fi
      [[ $# -eq 0 ]] || usage
      RUN_FLAGS+=(-T) # the daily timer has no terminal
      ;;
    --preflight)
      [[ $# -eq 1 ]] || usage
      ARGS+=(--preflight)
      HOST_MODE=1
      ;;
    --apply)
      [[ $# -eq 2 && "$2" =~ $HASH_RE ]] || usage
      ARGS+=(--apply "$2")
      HOST_MODE=1
      ;;
    --record)
      shift
      [[ $# -ge 1 && "$1" =~ $ID_RE ]] || usage
      ARGS+=(--record)
      ids=0
      while [[ $# -gt 0 && "$1" =~ $ID_RE ]]; do
        ARGS+=("$1")
        shift
        ids=$((ids + 1))
      done
      [[ "$ids" -le "$MAX_IDS" ]] || usage
      while [[ $# -gt 0 ]]; do
        case "$1" in
          --date | --due)
            [[ $# -ge 2 && "$2" =~ $DAY_RE ]] || usage
            ARGS+=("$1" "$2")
            shift 2
            ;;
          *) usage ;;
        esac
      done
      NEEDS_TTY=1
      ;;
    *) usage ;;
  esac
fi

# A typed yes needs a terminal. Over `ssh host pct exec` there is none, and the container would
# start without one and wait for input that can never arrive. Say so at once, changing nothing.
if [[ -n "$NEEDS_TTY" && ( -z "${SOC_TEST_BIN:-}" || -n "${SOC_TEST_ENFORCE_TTY:-}" ) && ! -t 3 ]]; then
  echo "refused: this asks for a typed yes and needs a terminal. Run it from a real terminal (for a container: 'ssh -t <host> pct enter <id>'), not through 'pct exec'. Nothing was changed." >&2
  exit 2
fi

mkdir -p "$STATE"
touch "$LOG"
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$LOG"; }
die() { log "FAILED: $*"; exit 1; }

# --- 1. the register clone: up to date, clean, at origin/main, signed ---------------------
[[ -d "$REPO/.git" ]] || die "$REPO is not a git clone of the key register"
if [[ -n "${SOC_KEYS_SSH_KEY:-}" ]]; then
  [[ -r "$SOC_KEYS_SSH_KEY" ]] || die "SOC_KEYS_SSH_KEY is not a readable file"
  export GIT_SSH_COMMAND="ssh -i $SOC_KEYS_SSH_KEY -o IdentitiesOnly=yes -o BatchMode=yes"
fi
git -C "$REPO" fetch -q origin main \
  || die "could not fetch origin/main in $REPO"
# Fast-forward only: a clone that has diverged is refused, never merged or reset here.
git -C "$REPO" merge -q --ff-only origin/main \
  || die "$REPO cannot be fast-forwarded to origin/main (diverged or has local commits)"
tree_state="$(git -C "$REPO" status --porcelain)" \
  || die "could not read the git status of $REPO"
[[ -z "$tree_state" ]] \
  || die "$REPO has uncommitted or untracked files; restore it to origin/main before planning"
COMMIT="$(git -C "$REPO" rev-parse HEAD)"
[[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]] || die "unexpected head commit id"
[[ "$COMMIT" == "$(git -C "$REPO" rev-parse origin/main)" ]] \
  || die "$REPO is not at origin/main"
SIG="$(git -C "$REPO" log -1 --format=%G? "$COMMIT")" \
  || die "could not read the signature status of $COMMIT"
[[ "$SIG" == G ]] \
  || die "the head commit's signature does not verify (git status '$SIG'); the host needs the signer's public key in its keyring"
[[ -d "$REPO/keys" ]] || die "$REPO/keys is missing"
log "register commit $COMMIT is at origin/main, signed by $(git -C "$REPO" log -1 --format=%GF "$COMMIT")"

# --- 2. what this host must have -------------------------------------------------------------
[[ -s "$STATE/env/image.env" ]] || die "no $STATE/env/image.env yet: run deploy.sh first"

# --- 3. the one-shot service, on this terminal (or with none, for the plan) -----------------
# The service runs as the image's user (10001) and keeps its files in this folder.
install -d -m 700 "$OUT"
[[ "$EUID" -ne 0 ]] || chown 10001:10001 "$OUT"
rm -f "$OUT/record.txt"
export SOC_ROTATE_COMMIT="$COMMIT" SOC_KEYS_SRC="$REPO"
set +e
if [[ -n "$HOST_MODE" ]]; then
  SRC="$HERE/../api/src"
  [[ -f "$SRC/soc_api/rotate/cli.py" ]] || die "$SRC/soc_api/rotate is missing"
  # The code about to hold the rights, as root, with the network, must be the reviewed code:
  # this checkout clean (deploy.sh keeps it at origin/main) and its head commit signed.
  PLATFORM="$(cd "$HERE/.." && pwd)"
  if [[ -n "${SOC_TEST_BIN:-}" ]]; then
    log "test mode: the soc-platform checkout's signature is not checked"
  else
    platform_state="$(git -C "$PLATFORM" status --porcelain)" \
      || die "could not read the git status of $PLATFORM"
    [[ -z "$platform_state" ]] \
      || die "$PLATFORM has uncommitted or untracked files; the code that holds the rights must be the reviewed code"
    PSIG="$(git -C "$PLATFORM" log -1 --format=%G? HEAD)" \
      || die "could not read the signature status of $PLATFORM"
    [[ "$PSIG" == G ]] \
      || die "the soc-platform checkout's head commit signature does not verify (git status '$PSIG')"
  fi
  command -v python3 >/dev/null || die "python3 is needed on the host for --preflight and --apply"
  # An empty environment on purpose, and -I so no PYTHON* variable or stray folder is read.
  # Standard input is the saved original (descriptor 3): it carries the rights.
  env -i PATH="$PATH" HOME="${HOME:-/root}" SOC_STATE_DIR="$STATE" \
    SOC_ROTATE_COMMIT="$COMMIT" SOC_ROTATE_KEYS_DIR="$REPO/keys" SOC_ROTATE_STATE="$OUT" \
    SOC_ROTATE_COMPOSE="$HERE/soc-compose.sh" \
    python3 -I -c 'import sys; sys.path.insert(0, sys.argv[1]); from soc_api.rotate.cli import main; raise SystemExit(main(sys.argv[2:]))' \
    "$SRC" ${ARGS[@]+"${ARGS[@]}"} <&3 3<&-
  rc=$?
else
  "$HERE/soc-compose.sh" --profile rotate run "${RUN_FLAGS[@]}" rotate ${ARGS[@]+"${ARGS[@]}"} <&3 3<&-
  rc=$?
fi
set -e

# --- 4. the record ------------------------------------------------------------------------------
if [[ -s "$OUT/record.txt" ]]; then
  # Written by the service: keep printable characters only, so nothing in it can drive root's
  # terminal (escape sequences) or forge extra lines in the log. An apply writes one line per
  # key, so up to 20 lines are kept.
  records="$(head -c 4000 "$OUT/record.txt" | head -n 20 | LC_ALL=C tr -cd '[:print:]\n')"
  printf '%s\n' "$records" >> "$LOG"
  echo
  echo "Record for the vault Build Log:"
  printf '%s\n' "$records" | sed 's/^/  /'
else
  log "no record was written by the rotate service (exit code $rc)"
fi
exit "$rc"
