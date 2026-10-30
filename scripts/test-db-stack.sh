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
# (The urgent-page chain near the end is the pager's full loop: push with buttons, a repeat,
# the phone Ack link, silence.)
# Then the pager worker (note 23, P2): init-worker.sh creates its files, a fake push
# server on the worker's own network receives what it sends, and the checks are: one
# push per case (a repeat in the same case adds none, a new rule adds one), the topic
# is only in the push body and never in the worker's log, the worker cannot reach the
# public app and the app cannot reach the push server, and soc_worker can read nothing.
# (The worker runs with SOC_ENV=dev here only so it may talk plain http to the fake.)
# Then the console's way in (note 24, P5a): the database listens on the host's loopback
# only; no container (the tunnel's network, the db network) can reach that port; soc_console
# can log in through it and call its case functions but read nothing; the database still
# cannot route out. (The outbound check runs on Linux only: Docker Desktop's network is not a Linux bridge.)
# Needs Docker only: the data directory is handed to uid 999 by a throwaway
# container, so no sudo is involved.
# Every secret here is a throwaway value for containers that live for this run.
set -euo pipefail

IMAGE="${1:?usage: test-db-stack.sh <image>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
FAILS=0
P=socdbtest
export SOC_API_IMAGE="$IMAGE" SOC_STATE_DIR="$WORK" SOC_ENV=prod COMPOSE_PROFILES=db

compose() { docker compose -p "$P" -f "$HERE/../deploy/compose.yml" "$@"; }
# Run a command as root in a throwaway container with the work directory mounted.
as_root() { docker run --rm --user 0 -v "$WORK:/w" --entrypoint "$1" "$IMAGE" "${@:2}"; }
cleanup() {
  docker rm -f "$P-fakentfy" "$P-fakelc" > /dev/null 2>&1 || true
  COMPOSE_PROFILES=db,worker compose down -v --remove-orphans > /dev/null 2>&1 || true
  as_root rm -rf /w/pgdata > /dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

pass() { echo "ok   - $*"; }
fail() { echo "FAIL - $*"; FAILS=$((FAILS + 1)); }
rand() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

SLUG="lc-$(rand 8)"
mkdir -p "$WORK"
# The same tool the host uses. SOC_INIT_TEST skips its root check and chown; the
# data directory is handed to uid 999 below by a container instead.
SOC_INIT_TEST=1 SOC_STATE_DIR="$WORK" "$HERE/../deploy/init-secrets.sh" "$SLUG" soc.example.com \
  > "$WORK/init.out" 2>&1 \
  && pass "init-secrets.sh created the host's secret files" \
  || { cat "$WORK/init.out"; fail "init-secrets.sh failed"; exit 1; }
grep -q "^Destination Host: https://soc.example.com/ingest/$SLUG$" "$WORK/init.out" 2> /dev/null \
  || grep -q "Destination Host: https://soc.example.com/ingest/$SLUG" "$WORK/init.out" \
  && pass "init-secrets.sh printed the webhook destination" || fail "init-secrets.sh did not print the destination"
rm -f "$WORK/init.out"
envval() { sed -n "s/^$2=//p" "$WORK/env/$1"; }
SUPER_PW="$(envval db.env POSTGRES_PASSWORD)"
OWNER_PW="$(envval db.env SOC_DB_OWNER_PASSWORD)"
INGEST_PW="$(envval db-owner.env SOC_INGEST_DB_PASSWORD)"

as_root chown 999:999 /w/pgdata
echo 'SOC_CONSOLE_USERS=ci@example.com' > "$WORK/env/console.env"
chmod 600 "$WORK/env/console.env"
# The source is bound to an organisation the self-test does not use, so its
# alerts must land in Unassigned.
cat > "$WORK/seed/smoke.json" <<JSON
{"client": {"slug": "smoke", "name": "Smoke Test Co", "status": "internal"},
 "sources": [{"slug": "$SLUG", "type": "limacharlie", "external_id": "00000000-0000-4000-8000-0000000000aa"}]}
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
# leaves it). $1 detect id, $2 gen_time in ms, $3 "good" or "bad" signature,
# $4 optional rule name (default smoke-test), $5 optional LimaCharlie priority (default 3).
deliver() {
  compose exec -T api python - "$1" "$2" "$3" "${4:-smoke-test}" "${5:-3}" << 'PY'
import hashlib, hmac, json, os, sys, urllib.error, urllib.request
detect_id, gen_time, mode, rule, prio = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], int(sys.argv[5])
slug, secrets = next(iter(json.loads(os.environ["SOC_INGEST_SECRETS"]).items()))
body = json.dumps({"author": "ci@example.com", "cat": "smoke", "detect_id": detect_id,
                   "gen_time": gen_time, "priority": prio, "source_rule": rule},
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
  docker run --rm --network "${P}_$net" -e SUPER_PW="$SUPER_PW" -e OWNER_PW="$OWNER_PW" -e INGEST_PW="$INGEST_PW" -e WORKER_PW="${WORKER_PW:-}" \
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

# --- the built-in self-test (runs inside the api container, like on the host) ---
HMAC="$(envval ingest.env SOC_INGEST_SECRETS | sed -n 's/.*\["\([0-9a-f]*\)"\].*/\1/p')"
OUT="$(compose exec -T api python -m soc_api.selftest --repeat)" && RC=0 || RC=$?
[[ "$RC" == 0 && "$(grep -c '^status=200 ' <<< "$OUT")" == 2 ]] \
  && pass "selftest: both deliveries accepted" || fail "selftest was not accepted twice (rc=$RC)"
ST_ID="$(sed -n '1s/.*detect_id=//p' <<< "$OUT")"
[[ -n "$ST_ID" && "$(rows "$ST_ID")" == 1 ]] && pass "selftest: stored once" || fail "selftest did not store exactly one row"
[[ "$(compose exec -T db psql -U postgres -d soc -Atc "SELECT c.slug FROM alert a JOIN client c ON c.id = a.client_id WHERE a.event_id = '$ST_ID'")" == unassigned ]] \
  && pass "selftest: landed in Unassigned" || fail "selftest alert did not land in Unassigned"
[[ -n "$HMAC" && "$OUT" != *"$HMAC"* && "$OUT" != *"$INGEST_PW"* && "$OUT" != *"$SLUG"* ]] \
  && pass "selftest: output holds no secret or source name" || fail "selftest output leaked a secret or the source name"

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
[[ -z "$(docker port "$(compose ps -q db)" 2> /dev/null | grep -v '^5432/tcp -> 127.0.0.1:5432$')" ]] \
  && pass "db publishes nothing but the loopback port" || fail "db publishes more than the loopback port"

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

# --- the pager worker ---------------------------------------------------------
FK="$P-fakentfy"
SOC_INIT_TEST=1 SOC_STATE_DIR="$WORK" "$HERE/../deploy/init-worker.sh" > "$WORK/init-worker.out" 2>&1 \
  && pass "init-worker.sh created the worker's secret files" \
  || { cat "$WORK/init-worker.out"; fail "init-worker.sh failed"; exit 1; }
rm -f "$WORK/init-worker.out"
WORKER_PW="$(envval worker-owner.env SOC_WORKER_DB_PASSWORD)"
TOPIC="$(envval worker.env SOC_NTFY_TOPIC)"
compose run --rm migrate && pass "migration job gave soc_worker its login" || { fail "migrate (worker login) failed"; exit 1; }

# The console's files come first: the phone-Ack key (pager-ack.env) is shared with the worker.
SOC_INIT_TEST=1 SOC_STATE_DIR="$WORK" "$HERE/../deploy/init-console-db.sh" > "$WORK/init-console.out" 2>&1 \
  && pass "init-console-db.sh created the console's secret files" \
  || { cat "$WORK/init-console.out"; fail "init-console-db.sh failed"; exit 1; }
rm -f "$WORK/init-console.out"
CONSOLE_PW="$(envval console-owner.env SOC_CONSOLE_DB_PASSWORD)"
SOC_INIT_TEST=1 SOC_STATE_DIR="$WORK" "$HERE/../deploy/init-reconcile.sh" > "$WORK/init-reconcile.out" 2>&1 \
  && pass "init-reconcile.sh created the catch-up worker's secret files" \
  || { cat "$WORK/init-reconcile.out"; fail "init-reconcile.sh failed"; exit 1; }
rm -f "$WORK/init-reconcile.out"
RECONCILE_PW="$(envval reconcile-owner.env SOC_RECONCILE_DB_PASSWORD)"

# The fake push server lives on the worker's own network, under the name the worker is told.
# The console's address and short re-send times (20 s and 60 s instead of 15 and 60 minutes)
# are not secret, so they go in policy.env.
cat > "$WORK/env/policy.env" << 'ENV'
SOC_NTFY_SERVER=http://fakentfy:8089
SOC_CONSOLE_BASE_URL=https://console.example.net
SOC_REPAGE_FIRST_SECONDS=20
SOC_REPAGE_SECOND_SECONDS=60
ENV
chmod 600 "$WORK/env/policy.env"
export COMPOSE_PROFILES=db,worker
SOC_ENV=dev compose create worker > /dev/null
docker run -d --name "$FK" --network "${P}_egress" --network-alias fakentfy --entrypoint python "$IMAGE" -c "
import http.server, json
LOG = []
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        LOG.append(self.rfile.read(int(self.headers.get('content-length') or 0)).decode())
        self.send_response(200); self.send_header('Content-Length', '0'); self.end_headers()
    def do_GET(self):
        b = json.dumps(LOG).encode()
        self.send_response(200); self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(('0.0.0.0', 8089), H).serve_forever()
" > /dev/null
fk_py() { docker exec "$FK" python -c "import json, urllib.request; L = json.load(urllib.request.urlopen('http://127.0.0.1:8089/')); $1"; }
npush() { fk_py 'print(len(L))'; }
wait_pushes() { # N: wait until the fake server holds at least N pushes
  for _ in $(seq 1 60); do [[ "$(npush 2> /dev/null || echo 0)" -ge "$1" ]] && return 0; sleep 1; done
  return 1
}
for _ in $(seq 1 30); do fk_py 'print(0)' > /dev/null 2>&1 && break; sleep 1; done

SOC_ENV=dev compose up -d worker > /dev/null
# The earlier deliveries are two cases (rule smoke-test, rule soc-selftest), both in
# Unassigned: so exactly two pushes.
wait_pushes 2 && pass "worker: the existing alerts were pushed" || { compose logs worker; fail "worker: no pushes arrived"; exit 1; }
sleep 12
[[ "$(npush)" == 2 ]] && pass "worker: exactly one push per case (two cases, two pushes)" || fail "worker: wrong number of pushes ($(npush))"
[[ "$(fk_py 'print(*sorted(json.loads(x)["title"] for x in L), sep="|")')" == "unassigned: smoke-test|unassigned: soc-selftest" ]] \
  && pass "worker: titles name the client and the rule" || fail "worker: unexpected titles"
[[ "$(fk_py "print(all(json.loads(x)['topic'] == '$TOPIC' and sorted(json.loads(x)) == ['actions', 'click', 'message', 'priority', 'title', 'topic'] and json.loads(x)['priority'] >= 4 for x in L))")" == True ]] \
  && pass "worker: JSON body with the topic, the console tap target and an Ack button, unassigned pages at priority 4 or more" || fail "worker: push body is not as expected"
[[ "$(compose exec -T db psql -U postgres -d soc -Atc "SELECT count(*) FILTER (WHERE status = 'sent'), count(*) FROM notification")" == "2|2" ]] \
  && pass "worker: both pages are recorded as sent" || fail "worker: pages are not all recorded as sent"

NOW2="$(( $(date +%s) * 1000 ))"
[[ "$(deliver "smoke-same-$(rand 6)" "$NOW2" good)" == 200 ]] || fail "worker: delivery for the same case was not a 200"
sleep 14
[[ "$(npush)" == 2 ]] && pass "worker: another alert in the same case adds no push" || fail "worker: a second push went out for the same case"
[[ "$(deliver "smoke-new-$(rand 6)" "$NOW2" good smoke-two)" == 200 ]] || fail "worker: delivery for a new rule was not a 200"
wait_pushes 3 && pass "worker: an alert for a new rule is a new case and one more push" || fail "worker: the new case was not pushed"
sleep 8
[[ "$(npush)" == 3 ]] && pass "worker: and only one" || fail "worker: more than one push for the new case"

for _ in $(seq 1 40); do
  [[ "$(docker inspect --format '{{.State.Health.Status}}' "$(compose ps -q worker)" 2> /dev/null)" == healthy ]] && break
  sleep 2
done
[[ "$(docker inspect --format '{{.State.Health.Status}}' "$(compose ps -q worker)")" == healthy ]] \
  && pass "worker: container is healthy" || fail "worker: container is not healthy"
WLOG="$(compose logs worker 2>&1)"
[[ "$WLOG" == *"page outcome=sent"* && "$WLOG" != *"$TOPIC"* && "$WLOG" != *"$WORKER_PW"* ]] \
  && pass "worker: logs the outcomes and neither the topic nor its password" || fail "worker: log is missing outcomes or leaks a secret"
[[ -z "$(docker port "$(compose ps -q worker)" 2> /dev/null)" ]] && pass "worker: publishes no host port" || fail "worker: publishes a host port"

# worker's networks: the database and the push server's network, never `default`
# (the tunnel's). It shares the internal db network with the app, as both are database
# clients; the app is not on the worker's egress network.
NETS="$(docker inspect --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$(compose ps -q worker)" | tr ' ' '\n' | grep -v '^$' | sort | tr '\n' ' ')"
[[ "$NETS" == "${P}_db ${P}_egress " ]] \
  && pass "worker: on the db and egress networks only, not on the tunnel's network" || fail "worker: unexpected networks: $NETS"
compose exec -T worker python -c "import socket; socket.getaddrinfo('db', 5432)" > /dev/null 2>&1 \
  && pass "worker: can resolve the database" || fail "worker: cannot resolve the database"
compose exec -T api python -c "import socket; socket.getaddrinfo('fakentfy', 8089)" > /dev/null 2>&1 \
  && fail "the public app CAN resolve the push server's network" || pass "the public app cannot reach the worker's egress network"
probe default "import socket; socket.getaddrinfo('fakentfy', 8089)" > /dev/null 2>&1 \
  && fail "a container on the tunnel's network CAN resolve the push server" || pass "a container on the tunnel's network cannot resolve the push server"
login soc_worker WORKER_PW && pass "soc_worker can log in" || fail "soc_worker cannot log in"
probe db "
import os, psycopg
c = psycopg.connect(host='db', dbname='soc', user='soc_worker', password=os.environ['WORKER_PW'])
try:
    c.execute('SELECT raw FROM alert')
except psycopg.errors.InsufficientPrivilege:
    raise SystemExit(0)
raise SystemExit(1)" > /dev/null 2>&1 \
  && pass "soc_worker cannot read the alert payload" || fail "soc_worker can read the alert payload"

# --- the console's database access (loopback publish) ---------------------------
compose run --rm migrate && pass "migration job gave soc_console its login" || { fail "migrate (console login) failed"; exit 1; }

# The catch-up worker's login, from a container on the database's own network (where its
# service will run): the cursor functions and the webhook's insert work, tables do not.
RECONCILE_CHECK='
import os, psycopg
c = psycopg.connect(host="db", dbname="soc", user="soc_reconcile", password=os.environ["PW"], connect_timeout=5, autocommit=True)
slug = os.environ["SLUG"]
before = c.execute("SELECT reconcile_cursor_get(%s)", (slug,)).fetchone()[0]
moved = c.execute("SELECT reconcile_cursor_advance(%s, now())", (slug,)).fetchone()[0]
back = c.execute("SELECT reconcile_cursor_advance(%s, now() - %s::interval)", (slug, "1 hour")).fetchone()[0]
same = back == moved
unknown = c.execute("SELECT ingest_alert(%s, %s, %s, %s, %s, %s, %s, NULL, now(), %s::jsonb)",
                    ("no-such-source", "t", "e", "r", "low", "s", "a", "{}")).fetchone()[0]
try:
    c.execute("SELECT raw FROM alert")
    read = "READ"
except psycopg.errors.InsufficientPrivilege:
    read = "denied"
print("ok", before is None, moved is not None, same, unknown, read)'
OUT="$(docker run --rm --network "${P}_db" -e PW="$RECONCILE_PW" -e SLUG="$SLUG" --entrypoint python "$IMAGE" -c "$RECONCILE_CHECK" 2>&1)"
[[ "$OUT" == "ok True True True unknown_source denied" ]] \
  && pass "soc_reconcile, on the db network: cursor moves forward only, webhook insert reachable, cannot read tables" \
  || fail "soc_reconcile check: $OUT"
[[ "$(compose exec -T db psql -U postgres -d soc -Atc "SELECT sources FROM reconcile_health()")" == 1 ]] \
  && pass "reconcile_health sees the cursor" || fail "reconcile_health does not see the cursor"

DBID="$(compose ps -q db)"
[[ "$(docker port "$DBID" 5432/tcp)" == "127.0.0.1:5432" ]] \
  && pass "db publishes exactly 127.0.0.1:5432" || fail "db publishes something else: $(docker port "$DBID")"
(exec 3<> /dev/tcp/127.0.0.1/5432) 2> /dev/null \
  && pass "the host's own loopback reaches the database port" || fail "the host cannot reach 127.0.0.1:5432"
for net in default db; do
  GW="$(docker network inspect --format '{{(index .IPAM.Config 0).Gateway}}' "${P}_$net")"
  probe "$net" "import socket; socket.create_connection(('$GW', 5432), timeout=3)" > /dev/null 2>&1 \
    && fail "a container on the $net network CAN reach the host's database port ($GW)" \
    || pass "a container on the $net network cannot reach the host's database port"
done
NETS="$(docker inspect --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$DBID" | tr ' ' '\n' | grep -v '^$' | sort | tr '\n' ' ')"
[[ "$NETS" == "${P}_db ${P}_dbhost " ]] \
  && pass "db is on the db and dbhost networks only" || fail "db is on unexpected networks: $NETS"
[[ "$(docker ps -q --filter "network=${P}_dbhost" | wc -l | tr -d ' ')" == 1 ]] \
  && pass "only the database is on the publishing network" || fail "something besides the database is on the publishing network"
[[ "$(docker network inspect --format '{{index .Options "com.docker.network.bridge.enable_ip_masquerade"}}' "${P}_dbhost")" == false ]] \
  && pass "the publishing network has no outbound NAT" || fail "the publishing network can masquerade"

# Through the published port, as the console would use it.
CONSOLE_CHECK='
import os, sys, psycopg
who, pw = sys.argv[1], os.environ["PW"]
try:
    c = psycopg.connect(host=os.environ["DBHOST"], port=5432, dbname="soc", user=who, password=pw, connect_timeout=5)
except psycopg.OperationalError:
    print("refused"); raise SystemExit(0)
if who != "soc_console":
    print("logged-in"); raise SystemExit(0)
case = c.execute("SELECT id FROM list_cases(%s, %s) LIMIT 1", ("all", 10)).fetchone()
ids = c.execute("SELECT count(*) FROM list_cases(%s, %s)", ("all", 50)).fetchone()[0]
acked = c.execute("SELECT ack_case(%s, %s)", (case[0], "ci@example.com")).fetchone()[0]
again = c.execute("SELECT ack_case(%s, %s)", (case[0], "ci@example.com")).fetchone()[0]
doc = c.execute("SELECT get_case(%s)", (case[0],)).fetchone()[0]
try:
    c.execute("SELECT raw FROM alert")
    read = "READ"
except psycopg.errors.InsufficientPrivilege:
    read = "denied"
c.close()
print("ok", ids > 0, acked, again, isinstance(doc["alerts"][0]["raw"], str), read)'
# Linux: a container on the host's own network reaches 127.0.0.1. Docker Desktop: the
# host's loopback is reached by name from a container (the same published port).
if [[ "$(uname)" == Linux ]]; then
  VIA=(--network host -e DBHOST=127.0.0.1)
else
  VIA=(-e DBHOST=host.docker.internal)
fi
OUT="$(docker run --rm "${VIA[@]}" -e PW="$CONSOLE_PW" --entrypoint python "$IMAGE" -c "$CONSOLE_CHECK" soc_console 2>&1)"
[[ "$OUT" == "ok True acked already True denied" ]] \
  && pass "soc_console, over the loopback port: lists, acknowledges once, reads a case as text, cannot read tables" \
  || fail "soc_console over the loopback port: $OUT"
[[ "$(docker run --rm "${VIA[@]}" -e PW="$SUPER_PW" --entrypoint python "$IMAGE" -c "$CONSOLE_CHECK" postgres 2>&1)" == refused ]] \
  && pass "the postgres superuser is refused over the loopback port too" || fail "the superuser can log in over the loopback port"

# The real console code against the real port: the queue, a case page, a valid Acknowledge,
# and a cross-site post that must be refused. (Same container route as above.)
cat > "$WORK/console_e2e.py" << 'PY'
import re
from fastapi.testclient import TestClient
from soc_api.config import Settings
from soc_api.main import create_console_app

s = Settings(env="prod", console_users="ci@example.com")
c = TestClient(create_console_app(s), base_url="https://console.example.net", follow_redirects=False)
h = {"Tailscale-User-Login": "ci@example.com"}
queue = c.get("/console/cases?status=open", headers=h)
ids = re.findall(r'/console/case/([0-9a-f-]{36})"', queue.text)
if queue.status_code != 200 or not ids:
    print("no-queue", queue.status_code)
    raise SystemExit(0)
case = ids[0]
page = c.get(f"/console/case/{case}", headers=h)
token = re.search(r'/ack">\s*<input type="hidden" name="token" value="([0-9a-f]{64})"', page.text)
post = {**h, "Sec-Fetch-Site": "same-origin", "Origin": "https://console.example.net",
        "Content-Type": "application/x-www-form-urlencoded"}
body = f"token={token.group(1)}"
cross = c.post(f"/console/case/{case}/ack", content=body, headers={**post, "Sec-Fetch-Site": "cross-site"})
still_open = "badge open" in c.get(f"/console/case/{case}", headers=h).text
ok = c.post(f"/console/case/{case}/ack", content=body, headers=post)
after = c.get(f"/console/case/{case}", headers=h).text
print("ok", cross.status_code, still_open, ok.status_code, "badge acknowledged" in after, "<script" in after.lower())
PY
if [[ "$(uname)" == Linux ]]; then DBHOST=127.0.0.1; else DBHOST=host.docker.internal; fi
OUT="$(docker run --rm "${VIA[@]}" --env-file "$WORK/env/console-db.env" --env-file "$WORK/env/pager-ack.env" \
  -e SOC_CONSOLE_DATABASE_URL="postgresql+psycopg://soc_console:${CONSOLE_PW}@${DBHOST}:5432/soc" \
  -v "$WORK/console_e2e.py:/console_e2e.py:ro" --entrypoint python "$IMAGE" /console_e2e.py 2>&1)"
[[ "$OUT" == "ok 403 True 303 True False" ]] \
  && pass "console pages: queue, case page, a cross-site Acknowledge refused, a valid one done, no script" \
  || fail "console pages against the real port: $OUT"

# --- an urgent page: pushed with buttons, sent again, then Acknowledged from the phone link ---
cat > "$WORK/phone_ack.py" << 'PY'
import os
from urllib.parse import urlsplit
from fastapi.testclient import TestClient
from soc_api.config import Settings
from soc_api.main import create_console_app

c = TestClient(create_console_app(Settings(env="prod", console_users="ci@example.com")),
               base_url="https://console.example.net", follow_redirects=False)
u = urlsplit(os.environ["ACK_URL"])
get = c.get(f"{u.path}?{u.query}", headers={"Tailscale-User-Login": "ci@example.com"})
r = c.post(f"{u.path}?{u.query}", headers={"Tailscale-User-Login": "ci@example.com"})
print(get.status_code, r.status_code, r.text)
PY
BEFORE="$(npush)"
URG="smoke-urgent-$(rand 6)"
[[ "$(deliver "$URG" "$(( $(date +%s) * 1000 ))" good smoke-urgent 7)" == 200 ]] || fail "urgent delivery was not a 200"
wait_pushes $((BEFORE + 1)) && pass "urgent page: pushed" || fail "urgent page: no push arrived"
[[ "$(fk_py 'p = json.loads(L[-1]); print(p["priority"], p["click"].startswith("https://console.example.net/console/case/"), [a["action"] + ":" + a["label"] for a in p["actions"]], p["title"].startswith("REPEAT"))')" \
   == "5 True ['http:Ack'] False" ]] \
  && pass "urgent page: priority 5, taps open the case page, an Ack button (no vendor link in this alert)" \
  || fail "urgent page: wrong click or buttons: $(fk_py 'print(json.loads(L[-1]).get("click"))')"
wait_pushes $((BEFORE + 2)) && pass "urgent page: sent again after the first interval" || fail "urgent page: no repeat arrived"
[[ "$(fk_py 'p = json.loads(L[-1]); print(p["title"].startswith("REPEAT: "), p["priority"])')" == "True 5" ]] \
  && pass "urgent page: the repeat says so and is still urgent" || fail "urgent page: the repeat is not marked"
ACK_URL="$(fk_py 'print([a["url"] for a in json.loads(L[-1])["actions"] if a["label"] == "Ack"][0])')"
OUT="$(docker run --rm "${VIA[@]}" --env-file "$WORK/env/console-db.env" --env-file "$WORK/env/pager-ack.env" \
  -e SOC_CONSOLE_DATABASE_URL="postgresql+psycopg://soc_console:${CONSOLE_PW}@${DBHOST}:5432/soc" -e ACK_URL="$ACK_URL" \
  -v "$WORK/phone_ack.py:/phone_ack.py:ro" --entrypoint python "$IMAGE" /phone_ack.py 2>&1)"
[[ "$OUT" == "405 200 Acknowledged." ]] \
  && pass "phone Ack: the pushed link acknowledges on POST and never on GET" \
  || fail "phone Ack: $OUT"
sleep 50
[[ "$(npush)" == $((BEFORE + 2)) ]] \
  && pass "after the Ack no further repeat is sent" || fail "a repeat was sent after the Ack ($(npush) pushes, expected $((BEFORE + 2)))"
[[ "$(compose exec -T db psql -U postgres -d soc -Atc "SELECT c.status, count(n.*) FILTER (WHERE n.status = 'sent'), count(n.*) FILTER (WHERE n.kind = 'repage2' AND n.status = 'sent') FROM soc_case c JOIN notification n ON n.case_id = c.id JOIN alert a ON a.case_id = c.id WHERE a.event_id = '$URG' GROUP BY c.status")" == "acknowledged|2|0" ]] \
  && pass "the case is acknowledged, two pages went out and the second repeat never did" \
  || fail "unexpected case or page state after the phone Ack"
# --- the catch-up worker ---------------------------------------------------------
# A fake vendor API (token, a list view without the rule name, detection time and priority,
# and the whole record by id) on the database network. It holds one detection the webhook
# never delivered, "detected" twenty minutes ago. The real `reconcile` service definition
# fetches it: stored once, with its rule, and paged as LATE.
LCF="$P-fakelc"
LC_OID="00000000-0000-4000-8000-0000000000aa"
LCKEY="$(rand 20)"
cat > "$WORK/fakelc.py" << 'PY'
import base64, gzip, http.server, json, time, urllib.parse

OID = "00000000-0000-4000-8000-0000000000aa"
NOW = time.time()
REC = {
    "cat": "CAT_STACK", "detect_id": "stack-reconciled-1",
    "detect": {"event": {"COMMAND_LINE": "/usr/bin/true"}},
    "detect_mtd": {"description": "Stack test."},
    "link": "https://app.limacharlie.io/orgs/o/sensors/s/timeline?time=1",
    "namespace": "general", "routing": {"hostname": "ws-demo-01", "oid": OID},
    "source": "o.i.s.2", "ts": int((NOW - 600) * 1000),
    "gen_time": int((NOW - 1200) * 1000), "priority": 4, "source_rule": "general.Stack Rule",
}
SUMMARY = {k: v for k, v in REC.items() if k not in ("gen_time", "priority", "source_rule")}

class H(http.server.BaseHTTPRequestHandler):
    def reply(self, code, doc=None):
        body = json.dumps(doc).encode() if doc is not None else b""
        self.send_response(code); self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)
    def do_POST(self):
        self.rfile.read(int(self.headers.get("content-length") or 0))
        self.reply(200, {"jwt": "aaa.bbb.ccc"})
    def do_GET(self):
        if self.headers.get("Authorization") != "Bearer aaa.bbb.ccc":
            return self.reply(401)
        parts = urllib.parse.urlsplit(self.path)
        q = dict(urllib.parse.parse_qsl(parts.query))
        if parts.path == f"/v1/insight/{OID}/detections":
            hit = int(q["start"]) * 1000 <= REC["ts"] <= int(q["end"]) * 1000
            raw = json.dumps([SUMMARY] if hit else []).encode()
            return self.reply(200, {"detects": base64.b64encode(gzip.compress(raw)).decode(), "next_cursor": None})
        if parts.path == f"/v1/insight/{OID}/detections/{REC['detect_id']}":
            return self.reply(200, {"detection": {"event": REC}})
        self.reply(404)
    def log_message(self, *a): pass

http.server.ThreadingHTTPServer(("0.0.0.0", 8090), H).serve_forever()
PY
docker run -d --name "$LCF" --network "${P}_db" --network-alias fakelc -v "$WORK/fakelc.py:/fakelc.py:ro" \
  --entrypoint python "$IMAGE" /fakelc.py > /dev/null
for _ in $(seq 1 30); do
  docker exec "$LCF" python -c "import socket; socket.create_connection(('127.0.0.1', 8090), 2)" > /dev/null 2>&1 && break
  sleep 1
done
SOC_INIT_TEST=1 SOC_STATE_DIR="$WORK" SOC_LC_RECONCILE_KEY="$LCKEY" SOC_LC_OID="$LC_OID" SOC_INGEST_LC_SLUG="$SLUG" \
  "$HERE/../deploy/init-reconcile-lc.sh" --restore > "$WORK/init-lc.out" 2>&1 \
  && pass "init-reconcile-lc.sh wrote the vendor-API file" \
  || { cat "$WORK/init-lc.out"; fail "init-reconcile-lc.sh failed"; exit 1; }
rm -f "$WORK/init-lc.out"
cat >> "$WORK/env/policy.env" << 'ENV'
SOC_RECONCILE_CATEGORIES=CAT_STACK,CAT_UNUSED
SOC_RECONCILE_API_URL=http://fakelc:8090
SOC_RECONCILE_JWT_URL=http://fakelc:8090/jwt
ENV
export COMPOSE_PROFILES=db,worker,reconcile
rec() { SOC_ENV=dev compose run --rm reconcile python -m soc_api.reconcile "$@" 2>&1; }

OUT="$(rec check --minutes 60)"
[[ "$OUT" == *"check ok: auth=ok window=60m listed=1 matching=1"* && "$OUT" == *"found at: detection.event=1"* \
   && "$OUT" == *"listed fields (1 records): detect_id=1 cat=1 source_rule=0 gen_time=0 priority=0"* && "$OUT" != *"$LCKEY"* ]] \
  && pass "reconcile check: auth works, the list view is a summary, the whole record has the rest" \
  || fail "reconcile check: $OUT"

BEFORE_LC="$(npush)"
OUT="$(rec once)"
[[ "$OUT" == *"reconcile outcome=ok windows=1 listed=1 kept=1 inserted=1 duplicate=0 skipped=0 malformed=0 enriched=1 degraded=0"* && "$OUT" != *"$LCKEY"* ]] \
  && pass "reconcile: a detection only the source had was fetched and stored (no key in the log)" \
  || fail "reconcile once: $OUT"
[[ "$(compose exec -T db psql -U postgres -d soc -Atc "SELECT count(*), min(rule), min(severity) FROM alert WHERE event_id = 'stack-reconciled-1'")" == "1|general.Stack Rule|medium" ]] \
  && pass "reconcile: stored once, with its rule and priority from the whole record" \
  || fail "reconcile: the stored alert is not as expected"
OUT="$(rec once)"
[[ "$OUT" == *"inserted=0 duplicate=1"* ]] && pass "reconcile: the next pass sees it again and stores nothing" || fail "reconcile second pass: $OUT"
[[ "$(compose exec -T db psql -U postgres -d soc -Atc "SELECT count(*) FROM alert WHERE event_id = 'stack-reconciled-1'")" == 1 ]] \
  && pass "reconcile: still exactly one alert" || fail "reconcile: the alert was stored twice"
wait_pushes $((BEFORE_LC + 1)) && pass "reconcile: the pager pushed it" || fail "reconcile: no push for the caught-up alert"
[[ "$(fk_py 'print(sum(json.loads(x)["title"] == "LATE: smoke: Stack Rule" for x in L))')" == 1 ]] \
  && pass "reconcile: the push says LATE, once" || fail "reconcile: the push is not marked LATE exactly once"
[[ "$(compose exec -T db psql -U postgres -d soc -Atc "SELECT sources FROM reconcile_health()")" == 1 ]] \
  && pass "reconcile: the pager's health view sees the cursor" || fail "reconcile: no cursor"

SOC_ENV=dev compose up -d reconcile > /dev/null
RID="$(compose ps -q reconcile)"
for _ in $(seq 1 40); do
  docker exec "$RID" python -c "import os; os.stat('/tmp/reconcile-health')" > /dev/null 2>&1 && break
  sleep 1
done
docker exec "$RID" python -c "import os; os.stat('/tmp/reconcile-health')" > /dev/null 2>&1 \
  && pass "reconcile service: running, and its health file is written" || fail "reconcile service: no health file"
[[ "$(docker inspect "$RID" --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}')" == "${P}_db ${P}_egress " ]] \
  && pass "reconcile service: on the database and egress networks only" || fail "reconcile service: unexpected networks"
[[ "$(docker inspect "$RID" --format '{{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}} {{len .HostConfig.PortBindings}}')" == "true [ALL] 0" ]] \
  && pass "reconcile service: read-only, no capabilities, nothing published" || fail "reconcile service: not hardened as declared"
compose stop reconcile > /dev/null

# The database has no way out: an outbound connection from its own container fails.
docker exec "$DBID" timeout 5 bash -c 'exec 3<> /dev/tcp/1.1.1.1/443' > /dev/null 2>&1 \
  && { [[ "$(uname)" == Linux ]] && fail "the database container CAN open an outbound connection" || echo "skip - outbound check (Docker Desktop's network is not a Linux bridge)"; } \
  || pass "the database container cannot open an outbound connection"

echo
[[ "$FAILS" -eq 0 ]] && echo "all database checks passed" || { echo "$FAILS database check(s) failed"; exit 1; }
