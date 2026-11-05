#!/usr/bin/env bash
# Proves the off-site container on the real compose file and the real restic image
# (note 26, row B1d). The cloud storage itself is not reachable from a test: the repository
# used here lives inside the container, so this checks the container, not the provider.
#
#   scripts/test-offsite-stack.sh
#
# Needs Docker and a non-root user. Checks: the pinned image starts under the service's
# hardening (read-only root, no capabilities); the container is on the egress network ONLY
# (no database network, not the tunnel's) and publishes nothing; the backup folder is
# mounted read-only; the key file reaches it as environment and nothing else; a real
# restic init, backup (with the flags offsite.sh uses, copied here; api/tests/test_offsite.py
# runs the real script against real restic), check and restore from the container round-trips
# the bytes; and soc-compose.sh's profiles do
# not start it.
# Every secret here is a throwaway value for a container that lives for this run.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
DEPLOY="$HERE/../deploy"
WORK="$(mktemp -d)"
FAILS=0
P=socoffsitetest
export SOC_STATE_DIR="$WORK" SOC_API_IMAGE=unused:none
unset COMPOSE_PROFILES

as_root() { docker run --rm --user 0 -v "$1:/w" --entrypoint "$2" restic/restic:0.19.1 "${@:3}"; }
compose() { docker compose -p "$P" -f "$DEPLOY/compose.yml" "$@"; }
cleanup() {
  docker rm -f "$P-held" > /dev/null 2>&1 || true
  compose down -v --remove-orphans > /dev/null 2>&1 || true
  as_root "$WORK" rm -rf /w/backups > /dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
pass() { echo "ok   - $*"; }
fail() { echo "FAIL - $*"; FAILS=$((FAILS + 1)); }

mkdir -p "$WORK/env" "$WORK/backups"
umask 077
printf '%s\n' \
  "RESTIC_REPOSITORY=/tmp/repo" \
  "RESTIC_PASSWORD=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')" \
  "AWS_ACCESS_KEY_ID=throwawaykeyid0123456789" \
  "AWS_SECRET_ACCESS_KEY=throwawaysecretthrowawaysecret" > "$WORK/env/offsite.env"
printf 'ciphertext-dump-%s\n' "$(head -c 2000 /dev/urandom | od -An -tx1 | tr -d ' \n')" \
  > "$WORK/backups/soc-20261104T061700Z.dump.age"
printf 'ciphertext-roles\n' > "$WORK/backups/soc-20261104T061700Z.globals.sql.age"
printf '%s  x\n' "$(printf 'x' | od -An -tx1 | tr -d ' \n')" > "$WORK/backups/soc-20261104T061700Z.sha256"
mkdir "$WORK/backups/.tmp.abc"
echo "PLAIN-MUST-NOT-LEAVE" > "$WORK/backups/.tmp.abc/soc.dump"
# On the host the sets belong to root with mode 600 and the container runs as root; make the
# test folder the same (a file owned by someone else cannot be opened without extra rights,
# which the container does not have).
as_root "$WORK" sh -c 'chown -R 0:0 /w/backups && chmod -R go-rwx /w/backups'

# --- the container, held open so it can be looked at ------------------------------------
compose run -d --no-deps --name "$P-held" --entrypoint sleep offsite 120 > /dev/null
NETS="$(docker inspect --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$P-held")"
[[ "$NETS" == "${P}_egress " ]] && pass "on the egress network only ($NETS)" \
  || fail "networks are: $NETS"
[[ -z "$(docker port "$P-held")" ]] && pass "publishes no port" || fail "a port is published"
[[ "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$P-held")" == true ]] \
  && pass "root filesystem is read-only" || fail "root filesystem is writable"
[[ "$(docker inspect --format '{{.HostConfig.CapDrop}}' "$P-held")" == "[ALL]" ]] \
  && pass "all capabilities dropped" || fail "capabilities are not dropped"
MOUNT_RW="$(docker inspect --format '{{range .Mounts}}{{.Destination}}={{.RW}} {{end}}' "$P-held")"
[[ "$MOUNT_RW" == "/backups=false " ]] && pass "the backup folder is the only mount, read-only" \
  || fail "mounts: $MOUNT_RW"
if docker exec "$P-held" sh -c 'touch /backups/x' > /dev/null 2>&1; then
  fail "the backup folder can be written to"
else pass "writing to the backup folder fails"; fi
if docker exec "$P-held" sh -c 'getent hosts db || nslookup db' > /dev/null 2>&1; then
  fail "the database name resolves from the container"
else pass "the database name does not resolve (no route to it)"; fi
docker exec "$P-held" sh -c 'test -n "$RESTIC_PASSWORD" && test -n "$AWS_SECRET_ACCESS_KEY" && test -z "$POSTGRES_PASSWORD"' \
  && pass "the key file arrives as environment, with no database secret" \
  || fail "environment is not what the key file says"
docker rm -f "$P-held" > /dev/null

# --- a real restic round trip through the service, with offsite.sh's flags ----------------
# Docker Desktop (a Mac or Windows laptop) cannot serve restic's reads of a bind mount
# (input/output error); Linux, which is what the host and CI run, can. There the test copies
# the folder into the container first, and says so: the flags, image and hardening are still
# what is checked, but the read-through-the-mount part only runs on Linux.
STAGE='SRC=/backups'
if docker info --format '{{.OperatingSystem}}' 2> /dev/null | grep -qi 'docker desktop'; then
  echo "note - Docker Desktop: copying the folder into the container before backing it up"
  STAGE='cp -a /backups /tmp/src; SRC=/tmp/src'
fi
OUT="$(compose run --rm -T --no-deps --entrypoint sh offsite -c "
  set -e
  $STAGE
  /usr/bin/restic init --no-cache > /dev/null
  /usr/bin/restic backup \$SRC --json --no-lock --no-cache --host soc --tag soc-backup \
    --exclude .lock --exclude '.tmp.*' > /tmp/b.json
  grep -q '\"snapshot_id\"' /tmp/b.json
  /usr/bin/restic check --no-lock --no-cache > /dev/null
  /usr/bin/restic ls latest --no-lock --no-cache | grep -v '^snapshot' | sort
  /usr/bin/restic restore latest --target /tmp/out --no-lock --no-cache > /dev/null
  cmp \"\$(find /tmp/out -name '*.dump.age')\" /backups/soc-20261104T061700Z.dump.age
  echo ROUNDTRIP-OK
" 2>&1)" || { echo "$OUT"; fail "the restic round trip failed"; OUT=""; }
[[ "$OUT" == *ROUNDTRIP-OK* ]] && pass "init, backup, check and restore round-trip the bytes" \
  || fail "no round trip"
[[ "$OUT" == *globals.sql.age* && "$OUT" == *.sha256* ]] && pass "all three files of the set were sent" \
  || fail "the set is incomplete in the repository"
if [[ "$OUT" == *PLAIN-MUST-NOT-LEAVE* || "$OUT" == *.tmp.* || "$OUT" == */.lock* ]]; then
  fail "a temporary file or the lock was sent"
else pass "the temporary folder and the lock were left out"; fi

# --- soc-compose.sh must not start it --------------------------------------------------------
if grep -q offsite "$DEPLOY/soc-compose.sh"; then fail "soc-compose.sh mentions the offsite profile"
else pass "soc-compose.sh does not turn the profile on"; fi
compose up -d --no-build > /dev/null 2>&1 || true
[[ -z "$(compose ps -q offsite 2> /dev/null)" ]] && pass "up -d does not start it" \
  || fail "up -d started the offsite container"

echo
if [[ "$FAILS" -ne 0 ]]; then echo "$FAILS offsite check(s) FAILED"; exit 1; fi
echo "all offsite checks passed"
