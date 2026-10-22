#!/usr/bin/env bash
# Proves the console cannot be reached from the public side (note 19, D1-D4).
#
#   scripts/test-console-isolation.sh <image>      e.g. soc-api:ci
#
# Starts the real compose services (public api on the bridge network, console on
# the host network), then acts like the tunnel container: a container on the
# compose network. It must not be able to reach the console, and the public app
# must answer 404 for /console whatever identity header a caller forges.
# Needs Docker with Linux host networking (a CI runner, not Docker Desktop).
set -euo pipefail

IMAGE="${1:?usage: test-console-isolation.sh <image>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
FAILS=0
export SOC_API_IMAGE="$IMAGE" SOC_STATE_DIR="$WORK" SOC_ENV=prod

mkdir -p "$WORK/env"
echo 'SOC_CONSOLE_USERS=ci@example.com' > "$WORK/env/console.env"

compose() { docker compose -p socisotest -f "$HERE/../deploy/compose.yml" "$@"; }
cleanup() { compose down -v --remove-orphans > /dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT

pass() { echo "ok   - $*"; }
fail() { echo "FAIL - $*"; FAILS=$((FAILS + 1)); }

# Run a Python snippet in a throwaway container on the compose network.
probe() {
  docker run --rm --network socisotest_default --add-host=hostgw:host-gateway \
    --entrypoint python "$IMAGE" -c "$1"
}

compose up -d api console
for _ in $(seq 1 30); do
  curl -fsS --max-time 2 http://127.0.0.1:8081/healthz > /dev/null 2>&1 \
    && curl -fsS --max-time 2 http://127.0.0.1:8080/healthz > /dev/null 2>&1 && break
  sleep 1
done

# Positive controls first: if these fail, the "unreachable" results below mean nothing.
curl -fsS --max-time 3 -H 'Tailscale-User-Login: ci@example.com' \
  http://127.0.0.1:8081/console > /dev/null \
  && pass "console answers an allowlisted login on the host loopback" \
  || fail "console does not answer on the host loopback (test setup is broken)"
code="$(curl -s -o /dev/null -w '%{http_code}' -H 'Tailscale-User-Login: attacker@example.com' http://127.0.0.1:8081/console)"
[[ "$code" == 403 ]] && pass "console refuses a login that is not on the allowlist" || fail "console answered $code for a stranger"
probe "import urllib.request as u; u.urlopen('http://api:8080/healthz', timeout=3)" \
  && pass "a container on the compose network can reach the public app" \
  || fail "probe cannot reach the public app (test setup is broken)"

# The point of the test: the console is unreachable from the tunnel's side.
GATEWAY="$(docker network inspect socisotest_default -f '{{(index .IPAM.Config 0).Gateway}}')"
for target in "console:8081" "$GATEWAY:8081" "hostgw:8081"; do
  if probe "import socket; socket.create_connection(('${target%:*}', ${target#*:}), timeout=3)" > /dev/null 2>&1; then
    fail "a container on the compose network CAN connect to the console via $target"
  else
    pass "a container on the compose network cannot connect to the console via $target"
  fi
done

# The public app has no console, even when the caller forges an allowed identity.
for path in /console /console/console.css; do
  code="$(docker run --rm --network socisotest_default --entrypoint python "$IMAGE" -c "
import urllib.request as u, urllib.error as e
r = u.Request('http://api:8080$path', headers={'Tailscale-User-Login': 'ci@example.com'})
try:
    print(u.urlopen(r, timeout=3).status)
except e.HTTPError as x:
    print(x.code)")"
  [[ "$code" == 404 ]] && pass "public app returns 404 for $path with a forged identity" || fail "public app returned $code for $path"
done

echo
[[ "$FAILS" -eq 0 ]] && echo "all isolation checks passed" || { echo "$FAILS isolation check(s) failed"; exit 1; }
