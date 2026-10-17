#!/usr/bin/env bash
# Deploy a signed soc-api image.
#
#   deploy.sh <tag>        e.g. deploy.sh edge   or   deploy.sh sha-60983cc
#
# 1. Verify the image signature with cosign: it must have been signed by this
#    repository's release workflow on main or a version tag. Anything else is refused.
# 2. Verify the signed SBOM attestation on the same image.
# 3. Pin the deployment to the verified digest (never the mutable tag), so the
#    image can't be swapped between verification and pull.
# 4. Start the stack, wait for health, and confirm /version reports the commit
#    that was signed. On any failure, roll back to the previous digest.
#
# Environment (defaults suit the Stage A container):
#   SOC_STATE_DIR   state root           /srv/soc
#   SOC_REPO        image repository     ghcr.io/mht-lab/soc-api
#   SOC_SIGNER      expected signer      https://github.com/MHT-LAB/soc-platform/.github/workflows/release.yml@refs/...
#   SOC_OVERLAY     edge overlay file    compose.stage-a.yml
set -euo pipefail

TAG="${1:?usage: deploy.sh <tag>}"
STATE="${SOC_STATE_DIR:-/srv/soc}"
REPO="${SOC_REPO:-ghcr.io/mht-lab/soc-api}"
SIGNER="${SOC_SIGNER:-^https://github\.com/MHT-LAB/soc-platform/\.github/workflows/release\.yml@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+)$}"
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

mkdir -p "$STATE/env"
touch "$LOG"

# --- 1-2. verify signature and SBOM attestation ---------------------------------
log "verifying $REPO:$TAG"
verified="$(cosign verify \
    --certificate-identity-regexp "$SIGNER" \
    --certificate-oidc-issuer "$ISSUER" \
    --output json "$REPO:$TAG")" || die "signature verification failed for $REPO:$TAG"

DIGEST="$(printf '%s' "$verified" | python3 -c 'import sys, json; print(json.load(sys.stdin)[0]["critical"]["image"]["docker-manifest-digest"])')"
SIGNED_SHA="$(printf '%s' "$verified" | python3 -c 'import sys, json; print(json.load(sys.stdin)[0]["optional"].get("githubWorkflowSha", ""))')"
[[ "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || die "unexpected digest: $DIGEST"

cosign verify-attestation --type spdxjson \
    --certificate-identity-regexp "$SIGNER" \
    --certificate-oidc-issuer "$ISSUER" \
    "$REPO@$DIGEST" > /dev/null || die "SBOM attestation verification failed"
log "verified $REPO@$DIGEST (commit ${SIGNED_SHA:0:12})"

# --- 3. pin to the digest, keep the previous one for rollback -----------------------
PREVIOUS=""
[[ -f "$IMAGE_ENV" ]] && PREVIOUS="$(grep -E '^SOC_API_IMAGE=' "$IMAGE_ENV" | cut -d= -f2- || true)"
write_image() { umask 077; printf 'SOC_API_IMAGE=%s\nSOC_STATE_DIR=%s\n' "$1" "$STATE" > "$IMAGE_ENV"; }
write_image "$REPO@$DIGEST"

# --- 4. start, wait for health, confirm the running commit ---------------------------
healthy() {
  for _ in $(seq 1 30); do
    if v="$(curl -fsS --max-time 2 http://127.0.0.1:8080/version 2>/dev/null)"; then
      [[ -z "$SIGNED_SHA" || "$v" == *"$SIGNED_SHA"* ]] && return 0
    fi
    sleep 2
  done
  return 1
}

compose pull --quiet
compose up -d --remove-orphans

if healthy; then
  log "deployed $REPO@$DIGEST"
  compose ps
  exit 0
fi

log "health check failed for $DIGEST"
if [[ -n "$PREVIOUS" && "$PREVIOUS" != "$REPO@$DIGEST" ]]; then
  log "rolling back to $PREVIOUS"
  write_image "$PREVIOUS"
  compose up -d --remove-orphans
  SIGNED_SHA="" healthy && log "rollback healthy" || log "rollback ALSO unhealthy: investigate"
fi
exit 1
