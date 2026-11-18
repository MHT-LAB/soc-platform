#!/usr/bin/env bash
# Put the detection rules in git onto the detection source. Run it as root on the host.
#
#   rules-deploy.sh
#
# 1. Bring the rules clone (default /opt/detection-packs) up to origin/main (fast-forward only,
#    over its own read-only deploy key), then require: a clean tree, a head commit exactly at
#    origin/main, and a head commit whose signature verifies (git reports status G). Anything
#    else is refused before anything is run.
# 2. Check the host has what the job needs: env/image.env (the host has been deployed) and
#    env/rules-lc.env (init-rules-lc.sh), mode 600.
# 3. Run the one-shot `rules` service (python -m soc_api.rules_deploy) on the terminal: it
#    checks the rules, shows the difference with the live rules, and asks for a typed yes.
#    deploy.sh never starts this service; only this script does.
# 4. Append the service's one-line record to rules-deploy.log and print it, for the vault Build
#    Log. The exit code is the service's: 0 done or nothing to do, 1 failed part-way, 2 refused
#    before changing anything, 3 not confirmed.
#
# Environment (defaults suit the Stage A container):
#   SOC_STATE_DIR      state root                              /srv/soc
#   SOC_RULES_REPO     the rules clone                         /opt/detection-packs
#   SOC_RULES_SSH_KEY  the clone's read-only deploy key, if git does not already know it
#   SOC_TEST_BIN       TESTS ONLY: directory searched first for docker. Refused for root, so
#                      nothing in the environment can swap a tool on a host.
set -euo pipefail

if [[ -n "${SOC_TEST_BIN:-}" && "$EUID" -eq 0 ]]; then
  echo "FAILED: SOC_TEST_BIN is for tests only and is refused for root" >&2
  exit 1
fi
if [[ "$EUID" -ne 0 && -z "${SOC_TEST_BIN:-}" ]]; then
  echo "FAILED: run as root" >&2
  exit 1
fi
# Don't depend on how the shell was opened (pct enter gives a minimal PATH).
export PATH="${SOC_TEST_BIN:+$SOC_TEST_BIN:}/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
# Never let the shell choose profiles or the commit: both come from this script.
unset COMPOSE_PROFILES SOC_RULES_COMMIT SOC_RULES_SRC
export SOC_ENV=prod

STATE="${SOC_STATE_DIR:-/srv/soc}"
REPO="${SOC_RULES_REPO:-/opt/detection-packs}"
HERE="$(cd "$(dirname "$0")" && pwd)"
LC_ENV="$STATE/env/rules-lc.env"
OUT="$STATE/rules-out"
LOG="$STATE/rules-deploy.log"

mkdir -p "$STATE"
touch "$LOG"
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$LOG"; }
die() { log "FAILED: $*"; exit 1; }

# --- 1. the rules clone: up to date, clean, at origin/main, signed -------------------
[[ -d "$REPO/.git" ]] || die "$REPO is not a git clone of the rules repository"
if [[ -n "${SOC_RULES_SSH_KEY:-}" ]]; then
  [[ -r "$SOC_RULES_SSH_KEY" ]] || die "SOC_RULES_SSH_KEY is not a readable file"
  export GIT_SSH_COMMAND="ssh -i $SOC_RULES_SSH_KEY -o IdentitiesOnly=yes -o BatchMode=yes"
fi
git -C "$REPO" fetch -q origin main \
  || die "could not fetch origin/main in $REPO"
# Fast-forward only: a clone that has diverged is refused, never merged or reset here.
git -C "$REPO" merge -q --ff-only origin/main \
  || die "$REPO cannot be fast-forwarded to origin/main (diverged or has local commits)"
tree_state="$(git -C "$REPO" status --porcelain)" \
  || die "could not read the git status of $REPO"
[[ -z "$tree_state" ]] \
  || die "$REPO has uncommitted or untracked files; restore it to origin/main before deploying"
COMMIT="$(git -C "$REPO" rev-parse HEAD)"
[[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]] || die "unexpected head commit id"
[[ "$COMMIT" == "$(git -C "$REPO" rev-parse origin/main)" ]] \
  || die "$REPO is not at origin/main"
SIG="$(git -C "$REPO" log -1 --format=%G? "$COMMIT")" \
  || die "could not read the signature status of $COMMIT"
[[ "$SIG" == G ]] \
  || die "the head commit's signature does not verify (git status '$SIG'); the host needs the signer's public key in its keyring"
[[ -d "$REPO/detections/orgs" ]] || die "$REPO/detections/orgs is missing"
log "rules commit $COMMIT is at origin/main, signed by $(git -C "$REPO" log -1 --format=%GF "$COMMIT")"

# --- 2. what this host must have ---------------------------------------------------------
[[ -s "$STATE/env/image.env" ]] || die "no $STATE/env/image.env yet: run deploy.sh first"
[[ -s "$LC_ENV" ]] || die "$LC_ENV is missing: run init-rules-lc.sh first"
mode="$(stat -c %a "$LC_ENV" 2>/dev/null || stat -f %Lp "$LC_ENV")"
[[ "$mode" == 600 ]] || die "$LC_ENV must be mode 600 (it is $mode)"

# --- 3. the one-shot service, on this terminal -------------------------------------------
# The service runs as the image's user (10001) and writes its record into this folder.
install -d -m 700 "$OUT"
[[ "$EUID" -ne 0 ]] || chown 10001:10001 "$OUT"
rm -f "$OUT/record.txt"
export SOC_RULES_COMMIT="$COMMIT" SOC_RULES_SRC="$REPO"
set +e
"$HERE/soc-compose.sh" --profile rules run --rm rules
rc=$?
set -e

# --- 4. the record -------------------------------------------------------------------------
if [[ -s "$OUT/record.txt" ]]; then
  record="$(head -c 1000 "$OUT/record.txt" | head -n 1)"
  printf '%s\n' "$record" >> "$LOG"
  echo
  echo "Record for the vault Build Log (and the CT 110 note):"
  printf '  %s\n' "$record"
else
  log "no record was written by the rules service (exit code $rc)"
fi
exit "$rc"
