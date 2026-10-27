#!/usr/bin/env bash
# Proves the database layer on the real compose services (note 22, row F1).
#
#   scripts/test-db-stack.sh <image>      e.g. soc-api:ci
#
# Starts db, runs the migration job and the seed CLI, starts the public app with
# an ingest source, then checks: a signed delivery is stored once and a repeat
# adds nothing; a bad signature is refused; a container on the tunnel's side
# (the default network) cannot resolve or reach the database; the postgres
# superuser is refused over the network while the service roles work; soc_ingest
# can read nothing; with the database stopped a delivery gets a 503 and stores
# nothing while /healthz stays up.
# Needs Docker and passwordless sudo (the data directory belongs to uid 999).
# Every secret here is a throwaway value for containers that live for this run.
set -euo pipefail

IMAGE="${1:?usage: test-db-stack.sh <image>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
FAILS=0
P=socdbtest
export SOC_API_IMAGE="$IMAGE" SOC_STATE_DIR="$WORK" SOC_ENV=prod COMPOSE_PROFILES=db

compose() { docker compose -p "$P" -f "$HERE/../deploy/compose.yml" "$@"; }
cleanup() { compose down -v --remove-orphans > /dev/null 2>&1 || true; sudo rm -rf "$WORK"; }
trap cleanup EXIT

pass() { echo "ok   - $*"; }
fail() { echo "FAIL - $*"; FAILS=$((FAILS + 1)); }
rand() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

SUPER_PW="$(rand 24)"; OWNER_PW="$(rand 24)"; INGEST_PW="$(rand 24)"; HMAC="$(rand 24)"
SLUG="lc-smoketest"

mkdir -p "$WORK/env" "$WORK/seed" "$WORK/pgdata"
sudo chown 999:999 "$WORK/pgdata"; sudo chmod 700 "$WORK/pgdata"
echo 'SOC_CONSOLE_USERS=ci@example.com' > "$WORK/env/console.env"
printf 'POSTGRES_PASSWORD=%s\nSOC_DB_OWNER_PASSWORD=%s\n' "$SUPER_PW" "$OWNER_PW" > "$WORK/env/db.env"
printf 'SOC_MIGRATE_URL=postgresql+psycopg://soc_owner:%s@db:5432/soc\nSOC_INGEST_DB_PASSWORD=%s\n' \
  "$OWNER_PW" "$INGEST_PW" > "$WORK/env/db-owner.env"
printf 'SOC_INGEST_SECRETS={"%s":["%s"]}\nSOC_INGEST_DATABASE_URL=postgresql+psycopg://soc_ingest:%s@db:5432/soc\n' \
  "$SLUG" "$HMAC" "$INGEST_PW" > "$WORK/env/ingest.env"
chmod 600 "$WORK"/env/*.env
cat > "$WORK/seed/smoke.json" <<JSON
{"client": {"slug": "smoke", "name": "Smoke Test Co", "status": "internal"},
 "sources": [{"slug": "$SLUG", "type": "limacharlie"}]}
JSON

wait_db() {
  for _ in $(seq 1 60); do
    [[ "$(docker inspect --format '{{.State.Health.Status}}' "$(compose ps -q db)" 2> /dev/null)" == healthy ]] && return 0
    sleep 2
  done
  return 1
}
wait_api() {
  for _ in $(seq 1 30); do curl -fsS --max-time 2 http://127.0.0.1:8080/healthz > /dev/null 2>&1 && return 0; sleep 1; done
  return 1
}
rows() { compose exec -T db psql -U postgres -d soc -Atc "SELECT count(*) FROM alert WHERE event_id = '$1'"; }

# Sign and POST one delivery from inside the api container (the secret never
# leaves it). $1 detect id, $2 gen_time in ms, $3 "good" or "bad" signature.
deliver() {
  compose exec -T api python - "$1" "$2" "$3" << 'PY'
import hashlib, hmac, json, os, sys, urllib.error, urllib.request
detect_id, gen_time, mode = sys.argv[1], int(sys.argv[2]), sys.argv[3]
slug, secrets = next(iter(json.loads(os.environ["SOC_INGEST_SECRETS"]).items()))
body = json.dumps({"author": "ci@example.com", "cat": "smoke", "detect_id": detect_id,
                   "gen_time": gen_time, "priority": 3, "source_rule": "smoke-test"},
                  separators=(",", ":"), sort_keys=True).encode()
sig = hmac.new(secrets[0].encode(), body, hashlib.sha256).hexdigest()
if mode == "bad":
    sig = "0" * 64
req = urllib.request.Request(f"http://127.0.0.1:8080/ingest/{slug}", data=body, method="POST",
                             headers={"Content-Type": "application/json", "lc-signature": sig})
try:
    print(urllib.request.urlopen(req, timeout=10).status)
except urllib.error.HTTPError as e:
    print(e.code)
PY
}

# A throwaway container on a given compose network, running a Python snippet.
probe() {
  local net="$1"; shift
  docker run --rm --network "${P}_$net" -e SUPER_PW="$SUPER_PW" -e OWNER_PW="$OWNER_PW" -e INGEST_PW="$INGEST_PW" \
    --entrypoint python "$IMAGE" -c "$1"
}

compose up -d db
wait_db && pass "db is healthy" || { compose logs db; fail "db did not become healthy"; exit 1; }
compose run --rm migrate && pass "migrations and soc_ingest login applied" || { fail "migrate failed"; exit 1; }
compose run --rm migrate && pass "running the migration job twice is harmless" || fail "migrate is not repeatable"
compose run --rm --entrypoint python migrate -m soc_api.seed /seed/smoke.json && pass "seed loaded" || { fail "seed failed"; exit 1; }
compose run --rm --entrypoint python migrate -m soc_api.seed /seed/smoke.json && pass "seeding twice is harmless" || fail "seed is not repeatable"
compose up -d api
wait_api && pass "public app is up" || { compose logs api; fail "public app did not start"; exit 1; }

NOW="$(( $(date +%s) * 1000 ))"
ID1="smoke-$(rand 8)"
[[ "$(deliver "$ID1" "$NOW" good)" == 200 ]] && pass "signed delivery accepted" || fail "signed delivery was not a 200"
[[ "$(rows "$ID1")" == 1 ]] && pass "exactly one row stored" || fail "delivery did not store exactly one row"
[[ "$(deliver "$ID1" "$NOW" good)" == 200 ]] && pass "repeat accepted" || fail "repeat was not a 200"
[[ "$(rows "$ID1")" == 1 ]] && pass "repeat added no row" || fail "repeat changed the row count"
[[ "$(deliver "$ID1-x" "$NOW" bad)" == 401 ]] && pass "bad signature refused (401)" || fail "bad signature was not a 401"
[[ "$(rows "$ID1-x")" == 0 ]] && pass "bad signature stored nothing" || fail "bad signature stored a row"

# --- network isolation ---
probe default "import socket; socket.getaddrinfo('db', 5432)" > /dev/null 2>&1 \
  && fail "a container on the tunnel's network CAN resolve db" \
  || pass "a container on the tunnel's network cannot resolve db"
DB_IP="$(docker inspect --format "{{(index .NetworkSettings.Networks \"${P}_db\").IPAddress}}" "$(compose ps -q db)")"
probe default "import socket; socket.create_connection(('$DB_IP', 5432), timeout=3)" > /dev/null 2>&1 \
  && fail "a container on the tunnel's network CAN connect to db by address" \
  || pass "a container on the tunnel's network cannot connect to db by address"
probe db "import socket; socket.create_connection(('db', 5432), timeout=3)" \
  && pass "a container on the db network can reach db (control)" \
  || fail "db is unreachable even from the db network (test setup is broken)"
[[ -z "$(docker port "$(compose ps -q db)" 2> /dev/null)" ]] && pass "db publishes no host port" || fail "db publishes a host port"

# --- roles over the network ---
login() { # user, password env var -> exit 0 if the server accepts the login
  probe db "
import os, psycopg
psycopg.connect(host='db', dbname='soc', user='$1', password=os.environ['$2'], connect_timeout=5).close()" > /dev/null 2>&1
}
login soc_owner OWNER_PW && pass "soc_owner can log in" || fail "soc_owner cannot log in"
login soc_ingest INGEST_PW && pass "soc_ingest can log in" || fail "soc_ingest cannot log in"
login postgres SUPER_PW && fail "the postgres superuser CAN log in over the network" || pass "the postgres superuser is refused over the network"
probe db "
import os, psycopg
c = psycopg.connect(host='db', dbname='soc', user='soc_ingest', password=os.environ['INGEST_PW'])
try:
    c.execute('SELECT 1 FROM alert')
except psycopg.errors.InsufficientPrivilege:
    raise SystemExit(0)
raise SystemExit(1)" > /dev/null 2>&1 \
  && pass "soc_ingest cannot read the alert table" || fail "soc_ingest can read the alert table"

# --- database outage: 503, nothing stored, /healthz stays up ---
compose stop db > /dev/null
ID2="smoke-down-$(rand 8)"
[[ "$(deliver "$ID2" "$NOW" good)" == 503 ]] && pass "database down: delivery gets a 503" || fail "database down: delivery was not a 503"
curl -fsS --max-time 3 http://127.0.0.1:8080/healthz > /dev/null && pass "database down: /healthz still answers" || fail "database down: /healthz stopped"
compose start db > /dev/null
wait_db || { fail "db did not come back"; exit 1; }
[[ "$(rows "$ID2")" == 0 ]] && pass "the refused delivery stored nothing" || fail "a 503 delivery was stored"
[[ "$(deliver "$ID2" "$NOW" good)" == 200 ]] && pass "after recovery the same delivery is accepted" || fail "app did not recover after the database came back"
[[ "$(rows "$ID2")" == 1 ]] && pass "and stored once" || fail "recovered delivery not stored once"

echo
[[ "$FAILS" -eq 0 ]] && echo "all database checks passed" || { echo "$FAILS database check(s) failed"; exit 1; }
