#!/bin/bash
# Replace pg_hba.conf so the postgres superuser cannot log in over the network,
# whatever its password. It still works on the container's own socket (reachable
# only with root on the host: `docker compose exec db psql -U postgres`), which
# is how a lost password gets reset. Runs last (name order); the server that
# starts after the init scripts reads the new file.
set -euo pipefail

cat > "$PGDATA/pg_hba.conf" <<'HBA'
local   all   all            trust
host    all   postgres  all  reject
host    all   all       all  scram-sha-256
HBA
