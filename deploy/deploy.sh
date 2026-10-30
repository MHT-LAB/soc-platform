#!/usr/bin/env bash
# Deploy a signed soc-api image.
#
#   deploy.sh <tag>        e.g. deploy.sh edge   or   deploy.sh sha-60983cc
#
# 1. Verify the image signature with cosign. The signing certificate must come
#    from this repository's release workflow, on main or a version tag, run by a
#    push. Anything else is refused.
# 2. Verify the signed SBOM attestation on the same image.
# 2b. Require the commit the image was built from to be on main in this host's
#    clone, and make cosign prove the signature names exactly that commit. A
#    tag or branch run of the release workflow also gets a valid signature, so
#    the signature alone doesn't prove the code was reviewed and merged.
# 2c. Require the host's clone (which supplies this script and the compose files)
#    to be clean and exactly at origin/main, so a stale or edited checkout can't
#    run a new image with an old or modified compose layout.
# 3. Pin the deployment to the verified digest (never the mutable tag), so the
#    image can't be swapped between verification and pull.
# 3b. When the host has a database (env/db.env and env/db-owner.env), start it,
#    wait until it is healthy, and run the migrations with the new image BEFORE
#    anything is swapped. A failed migration restores the previous image.env and
#    stops; the running api and console are never touched. Migrations therefore
#    have to keep working with the previous image (expand, then contract): a
#    rollback swaps the image only and never runs a downgrade.
# 3c. When env/worker.env exists (deploy/init-worker.sh) and the host has a database, the
#    pager worker profile is on too: the migration job gives its database role a
#    login, and `up` starts it. A worker file without a database is refused.
# 3d. The same for the catch-up worker, once both env/reconcile-db.env and
#    env/reconcile-lc.env exist (the first alone only gives its database role a login).
# 4. Start the stack (public api and host-network console), wait for both to be
#    healthy, and confirm both containers use exactly the verified digest. On any
#    failure, roll back to the previous one.
#
# Environment (defaults suit the Stage A container):
#   SOC_STATE_DIR   state root           /srv/soc
#   SOC_REPO        image repository     ghcr.io/mht-lab/soc-api
#   SOC_SOURCE      source repository    MHT-LAB/soc-platform
#   SOC_OVERLAY     edge overlay file    compose.stage-a.yml
#   SOC_SOURCE_DIR  git clone to check   the repository this script lives in
#   SOC_TEST_BIN    TESTS ONLY: directory searched first for cosign, docker, curl
set -euo pipefail

# SOC_TEST_BIN lets the tests put fake cosign/docker first. It is refused for
# root, which is how the real deploy runs, so it can never swap tools on a host.
# $EUID is a bash builtin, checked before PATH changes, so no fake "id" can lie.
if [[ -n "${SOC_TEST_BIN:-}" && "$EUID" -eq 0 ]]; then
  echo "FAILED: SOC_TEST_BIN is for tests only and is refused for root" >&2
  exit 1
fi
# Don't depend on how the shell was opened (pct enter gives a minimal PATH).
export PATH="${SOC_TEST_BIN:+$SOC_TEST_BIN:}/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
# Compose reads SOC_ENV from the shell; never let a stray SOC_ENV=dev in the
# operator's terminal turn the allowlist off and the API docs on.
export SOC_ENV=prod

TAG="${1:?usage: deploy.sh <tag>}"
STATE="${SOC_STATE_DIR:-/srv/soc}"
REPO="${SOC_REPO:-ghcr.io/mht-lab/soc-api}"
SOURCE="${SOC_SOURCE:-MHT-LAB/soc-platform}"
SIGNER="^https://github\.com/${SOURCE}/\.github/workflows/release\.yml@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+)$"
ISSUER="https://token.actions.githubusercontent.com"
HERE="$(cd "$(dirname "$0")" && pwd)"
OVERLAY="${SOC_OVERLAY:-compose.stage-a.yml}"
IMAGE_ENV="$STATE/env/image.env"
LOG="$STATE/deploy.log"

log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$LOG"; }
die() { log "FAILED: $*"; exit 1; }

# Profiles are decided below, from the files on the host; never from the shell.
unset COMPOSE_PROFILES

compose() {
  docker compose -p soc \
    -f "$HERE/compose.yml" -f "$HERE/$OVERLAY" \
    --env-file "$IMAGE_ENV" "$@"
}

# Identity checks shared by both verifications: who signed, from which
# repository, triggered how.
IDENTITY=(
  --certificate-identity-regexp "$SIGNER"
  --certificate-oidc-issuer "$ISSUER"
  --certificate-github-workflow-repository "$SOURCE"
  --certificate-github-workflow-trigger push
)

mkdir -p "$STATE/env"
touch "$LOG"

# The API refuses to start in prod without a console allowlist. Say so here,
# before anything on the host changes, instead of via a failed health check.
# A login is anything other than quotes, spaces and commas after the "=".
CONSOLE_USERS_LINE="^SOC_CONSOLE_USERS=[[:space:]\"']*[^[:space:],\"']"
grep -qE "$CONSOLE_USERS_LINE" "$STATE/env/console.env" 2>/dev/null \
  || die "$STATE/env/console.env must set SOC_CONSOLE_USERS=<login>[,<login>...]"

# The database is optional until the host has its secrets: both files or neither.
# Half a setup is refused here, before anything changes, rather than skipped.
DB_ENV="$STATE/env/db.env"
DB_OWNER_ENV="$STATE/env/db-owner.env"
if [[ -s "$DB_ENV" && -s "$DB_OWNER_ENV" ]]; then
  [[ -d "$STATE/pgdata" ]] \
    || die "$STATE/pgdata is missing (create it owned by 999:999, mode 700)"
  mkdir -p "$STATE/seed"
  export COMPOSE_PROFILES=db
  DB=1
elif [[ -e "$DB_ENV" || -e "$DB_OWNER_ENV" ]]; then
  die "$DB_ENV and $DB_OWNER_ENV must both exist and be non-empty (or neither)"
else
  DB=0
fi

# The pager worker is optional too (init-worker.sh creates env/worker.env). It needs the
# database, so a worker file without one is refused here, before anything changes.
WORKER_ENV="$STATE/env/worker.env"
if [[ -s "$WORKER_ENV" ]]; then
  [[ "$DB" == 1 ]] \
    || die "$WORKER_ENV exists but this host has no database (env/db.env and env/db-owner.env)"
  export COMPOSE_PROFILES=db,worker
elif [[ -e "$WORKER_ENV" ]]; then
  die "$WORKER_ENV is empty; remove it, or restore it with init-worker.sh --restore"
fi

# The catch-up worker needs its database file (init-reconcile.sh) and its vendor-API file
# (init-reconcile-lc.sh). The first alone is fine: the migration job gives the database role
# its login and the service stays off until the second exists. The second without the
# first, or either empty, or either without a database, is refused here.
RECONCILE_DB_ENV="$STATE/env/reconcile-db.env"
RECONCILE_LC_ENV="$STATE/env/reconcile-lc.env"
if [[ -s "$RECONCILE_DB_ENV" && -s "$RECONCILE_LC_ENV" ]]; then
  [[ "$DB" == 1 ]] \
    || die "$RECONCILE_LC_ENV exists but this host has no database (env/db.env and env/db-owner.env)"
  export COMPOSE_PROFILES="${COMPOSE_PROFILES:+$COMPOSE_PROFILES,}reconcile"
elif [[ -e "$RECONCILE_LC_ENV" ]]; then
  die "$RECONCILE_LC_ENV needs a non-empty $RECONCILE_DB_ENV (init-reconcile.sh) and must not be empty itself"
elif [[ -e "$RECONCILE_DB_ENV" && ! -s "$RECONCILE_DB_ENV" ]]; then
  die "$RECONCILE_DB_ENV is empty; remove it, or restore it with init-reconcile.sh --restore"
fi

# The Stage A edge is a locally managed tunnel. Without its config and
# credentials the tunnel would crash-loop after the swap; stop here instead.
# cloudflared requires a catch-all; this checks it exists (order is checked in
# the deploy repo's CI with `cloudflared tunnel ingress rule`).
if [[ "$OVERLAY" == compose.stage-a.yml ]]; then
  TUNNEL_DIR="$STATE/tunnel"
  [[ -s "$TUNNEL_DIR/config.yml" ]] \
    || die "$TUNNEL_DIR/config.yml is missing (install it from the deploy repo)"
  CREDS="$(sed -nE 's#^credentials-file:[[:space:]]*/etc/cloudflared/([A-Za-z0-9-]+\.json)[[:space:]]*$#\1#p' "$TUNNEL_DIR/config.yml")"
  [[ -n "$CREDS" ]] \
    || die "$TUNNEL_DIR/config.yml must set credentials-file: /etc/cloudflared/<tunnel id>.json"
  [[ -s "$TUNNEL_DIR/$CREDS" ]] || die "tunnel credentials $TUNNEL_DIR/$CREDS are missing"
  grep -qE '^[[:space:]]*-[[:space:]]*service:[[:space:]]*http_status:404[[:space:]]*$' "$TUNNEL_DIR/config.yml" \
    || die "$TUNNEL_DIR/config.yml must include the catch-all rule '- service: http_status:404'"
fi

# --- 1-2. verify signature and SBOM attestation ---------------------------------
log "verifying $REPO:$TAG"
verified="$(cosign verify "${IDENTITY[@]}" --output json "$REPO:$TAG")" \
  || die "signature verification failed for $REPO:$TAG"

DIGEST="$(printf '%s' "$verified" | python3 -c 'import sys, json; print(json.load(sys.stdin)[0]["critical"]["image"]["docker-manifest-digest"])')"
[[ "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || die "unexpected digest: $DIGEST"

cosign verify-attestation --type spdxjson "${IDENTITY[@]}" "$REPO@$DIGEST" > /dev/null \
  || die "SBOM attestation verification failed"
log "verified $REPO@$DIGEST"

# --- 2b. the signed image must come from a commit that is on main -----------------
# The image records the commit it was built from. Trust that label only after
# both checks: the commit is on main in this host's clone, and cosign confirms the
# signing certificate names that exact commit (a forged label fails there).
# Nothing on the host has changed yet, so a refusal here leaves it as it was.
SRC_DIR="${SOC_SOURCE_DIR:-$HERE/..}"
REV="$(docker buildx imagetools inspect "$REPO@$DIGEST" --format '{{json .Image.Config.Labels}}' \
  | python3 -c 'import sys, json; print(json.load(sys.stdin).get("org.opencontainers.image.revision", ""))')" \
  || die "could not read the image's source commit label"
# Never echo the label: it is attacker-controlled text until it passes this check.
[[ "$REV" =~ ^[0-9a-f]{40}$ ]] || die "the image has no valid source commit label"
git -C "$SRC_DIR" fetch -q origin main \
  || die "could not fetch origin/main in $SRC_DIR to check the image's source commit"
# --- 2c. the host's working tree must be clean and exactly at origin/main ----------
# This script and the compose files run from this clone. Untracked files count as
# dirty (porcelain lists them) so a stray override file is refused too.
tree_state="$(git -C "$SRC_DIR" status --porcelain)" \
  || die "could not read the git status of $SRC_DIR"
[[ -z "$tree_state" ]] \
  || die "$SRC_DIR has uncommitted or untracked files; restore it to origin/main before deploying"
[[ "$(git -C "$SRC_DIR" rev-parse HEAD)" == "$(git -C "$SRC_DIR" rev-parse origin/main)" ]] \
  || die "$SRC_DIR is not at origin/main (behind, ahead or diverged); run git pull --ff-only first"
git -C "$SRC_DIR" merge-base --is-ancestor "$REV" origin/main \
  || die "the image was built from $REV, which is not on main"
cosign verify "${IDENTITY[@]}" --certificate-github-workflow-sha "$REV" "$REPO@$DIGEST" > /dev/null \
  || die "the signature does not name commit $REV; the image's commit label is not what was signed"
log "source commit $REV is on main"

# --- 3. pin to the digest, keep the previous one for rollback -----------------------
PREVIOUS=""
[[ -f "$IMAGE_ENV" ]] && PREVIOUS="$(grep -E '^SOC_API_IMAGE=' "$IMAGE_ENV" | cut -d= -f2- || true)"
write_image() { umask 077; printf 'SOC_API_IMAGE=%s\nSOC_STATE_DIR=%s\n' "$1" "$STATE" > "$IMAGE_ENV"; }
write_image "$REPO@$DIGEST"

# --- 4. start, wait for health, confirm the running image is the verified one -------
# Both services (public api, host-network console) must run the verified image.
running_digest_ok() {
  local svc cid img
  for svc in api console; do
    cid="$(compose ps -q "$svc")" && [[ -n "$cid" ]] || return 1
    img="$(docker inspect --format '{{.Image}}' "$cid")"
    docker image inspect --format '{{join .RepoDigests "\n"}}' "$img" | grep -qxF "$1" || return 1
  done
}

healthy() {
  for _ in $(seq 1 30); do
    if curl -fsS --max-time 2 http://127.0.0.1:8080/healthz > /dev/null 2>&1 \
      && curl -fsS --max-time 2 http://127.0.0.1:8081/healthz > /dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  return 1
}

compose pull --quiet

if [[ "$DB" == 1 ]]; then
  # Put image.env back as it was: nothing has been swapped yet, so the host keeps
  # running exactly what it ran before.
  restore_image() {
    if [[ -n "$PREVIOUS" ]]; then write_image "$PREVIOUS"; else rm -f "$IMAGE_ENV"; fi
  }
  db_healthy() {
    local cid status
    for _ in $(seq 1 60); do
      cid="$(compose ps -q db)" || cid=""
      if [[ -n "$cid" ]]; then
        status="$(docker inspect --format '{{.State.Health.Status}}' "$cid" 2> /dev/null || true)"
        [[ "$status" == healthy ]] && return 0
      fi
      sleep 2
    done
    return 1
  }
  log "starting the database"
  compose up -d db || { restore_image; die "the database did not start; nothing was swapped"; }
  db_healthy || { restore_image; die "the database is not healthy; nothing was swapped"; }
  log "running migrations with the new image"
  compose run --rm migrate \
    || { restore_image; die "migration failed; previous image restored, nothing was swapped"; }
  log "migrations applied"
else
  log "no database configured on this host (env/db.env and env/db-owner.env); skipping migrations"
fi

compose up -d --remove-orphans

if healthy && running_digest_ok "$REPO@$DIGEST"; then
  build="$(curl -fsS --max-time 2 http://127.0.0.1:8080/version || echo '{}')"
  log "deployed $REPO@$DIGEST build=$build"
  compose ps
  exit 0
fi

log "health or digest check failed for $DIGEST"
if [[ -n "$PREVIOUS" && "$PREVIOUS" != "$REPO@$DIGEST" ]]; then
  log "rolling back to $PREVIOUS"
  write_image "$PREVIOUS"
  compose up -d --remove-orphans
  if healthy && running_digest_ok "$PREVIOUS"; then
    log "rollback healthy"
  else
    log "rollback ALSO unhealthy: investigate"
  fi
fi
exit 1
