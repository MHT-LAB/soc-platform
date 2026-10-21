#!/usr/bin/env bash
# Deploy a signed soc-api image.
#
#   deploy.sh <tag>        e.g. deploy.sh edge   or   deploy.sh sha-60983cc
#
# 1. Verify the image signature with cosign. The signing certificate must come
#    from this repository's release workflow, on main or a version tag, run by a
#    push. Anything else is refused.
# 2. Verify the signed SBOM attestation on the same image.
# 3. Pin the deployment to the verified digest (never the mutable tag), so the
#    image can't be swapped between verification and pull.
# 4. Start the stack, wait for health, and confirm the running container uses
#    exactly the verified digest. On any failure, roll back to the previous one.
#
# Environment (defaults suit the Stage A container):
#   SOC_STATE_DIR   state root           /srv/soc
#   SOC_REPO        image repository     ghcr.io/mht-lab/soc-api
#   SOC_SOURCE      source repository    MHT-LAB/soc-platform
#   SOC_OVERLAY     edge overlay file    compose.stage-a.yml
set -euo pipefail

# Don't depend on how the shell was opened (pct enter gives a minimal PATH).
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
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

# --- 1-2. verify signature and SBOM attestation ---------------------------------
log "verifying $REPO:$TAG"
verified="$(cosign verify "${IDENTITY[@]}" --output json "$REPO:$TAG")" \
  || die "signature verification failed for $REPO:$TAG"

DIGEST="$(printf '%s' "$verified" | python3 -c 'import sys, json; print(json.load(sys.stdin)[0]["critical"]["image"]["docker-manifest-digest"])')"
[[ "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || die "unexpected digest: $DIGEST"

cosign verify-attestation --type spdxjson "${IDENTITY[@]}" "$REPO@$DIGEST" > /dev/null \
  || die "SBOM attestation verification failed"
log "verified $REPO@$DIGEST"

# --- 3. pin to the digest, keep the previous one for rollback -----------------------
PREVIOUS=""
[[ -f "$IMAGE_ENV" ]] && PREVIOUS="$(grep -E '^SOC_API_IMAGE=' "$IMAGE_ENV" | cut -d= -f2- || true)"
write_image() { umask 077; printf 'SOC_API_IMAGE=%s\nSOC_STATE_DIR=%s\n' "$1" "$STATE" > "$IMAGE_ENV"; }
write_image "$REPO@$DIGEST"

# --- 4. start, wait for health, confirm the running image is the verified one -------
running_digest_ok() {
  local cid img
  cid="$(compose ps -q api)" && [[ -n "$cid" ]] || return 1
  img="$(docker inspect --format '{{.Image}}' "$cid")"
  docker image inspect --format '{{join .RepoDigests "\n"}}' "$img" | grep -qxF "$1"
}

healthy() {
  for _ in $(seq 1 30); do
    if curl -fsS --max-time 2 http://127.0.0.1:8080/healthz > /dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  return 1
}

compose pull --quiet
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
