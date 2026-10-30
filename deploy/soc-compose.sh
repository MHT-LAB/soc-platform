#!/usr/bin/env bash
# Run docker compose against the deployed stack exactly as deploy.sh does: same
# project, compose files, pinned image and profiles. Use it for one-off jobs on the
# host, never to deploy (that is deploy.sh, which verifies the image first).
#
#   deploy/soc-compose.sh ps
#   deploy/soc-compose.sh exec db psql -U postgres -d soc
#   deploy/soc-compose.sh run --rm --entrypoint python migrate -m soc_api.seed /seed/<file>.json
#
# Environment: SOC_STATE_DIR (default /srv/soc), SOC_OVERLAY (default compose.stage-a.yml).
set -euo pipefail

STATE="${SOC_STATE_DIR:-/srv/soc}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OVERLAY="${SOC_OVERLAY:-compose.stage-a.yml}"
IMAGE_ENV="$STATE/env/image.env"

[[ -s "$IMAGE_ENV" ]] || { echo "no $IMAGE_ENV yet: run deploy.sh first" >&2; exit 1; }
[[ $# -gt 0 ]] || { echo "usage: soc-compose.sh <compose command> [args...]" >&2; exit 2; }

# Same rule as deploy.sh: the db profile follows the files on the host, never the shell.
unset COMPOSE_PROFILES
if [[ -s "$STATE/env/db.env" && -s "$STATE/env/db-owner.env" ]]; then
  export COMPOSE_PROFILES=db
fi

# ...and so does the worker profile: env/worker.env (with the database) turns it on.
if [[ -n "${COMPOSE_PROFILES:-}" && -s "$STATE/env/worker.env" ]]; then
  export COMPOSE_PROFILES=db,worker
fi

# ...and the catch-up worker's: both of its files (and the database) turn it on.
if [[ -n "${COMPOSE_PROFILES:-}" && -s "$STATE/env/reconcile-db.env" && -s "$STATE/env/reconcile-lc.env" ]]; then
  export COMPOSE_PROFILES="$COMPOSE_PROFILES,reconcile"
fi

exec docker compose -p soc -f "$HERE/compose.yml" -f "$HERE/$OVERLAY" --env-file "$IMAGE_ENV" "$@"
