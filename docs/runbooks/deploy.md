# Runbook: deploy

## What a deploy guarantees
Only an image signed by this repository's release workflow (on `main` or a
version tag, triggered by a push) can run. The deploy pins to the verified
**digest**, checks the signed SBOM attestation, waits for health, and confirms
the running container's image digest is exactly the verified one. Any failure
rolls back to the previous digest. The build's commit (from `/version`) is
recorded in the deploy log.

## Host layout (Stage A container)
| Path | Contents | Mode |
|---|---|---|
| `/opt/soc-platform` | read-only clone of this repo (deploy key) | root |
| `/srv/soc/tunnel/config.yml` | the tunnel's ingress rules, installed from the private deploy repo | 644 |
| `/srv/soc/tunnel/<tunnel id>.json` | the tunnel's credentials (runs this one tunnel, nothing else), owned by the cloudflared container user | 400 |
| `/srv/soc/env/image.env` | the verified image digest, written by `deploy.sh` | 600 |
| `/srv/soc/env/db.env`, `db-owner.env` | the database's secrets (see [database.md](database.md)); both or neither | 600 |
| `/srv/soc/pgdata` | PostgreSQL's data, owned by uid 999, so it is inside the container's nightly backup | 700 |
| `/srv/soc/seed/` | tenant seed files for `python -m soc_api.seed`, mounted read-only into the migration job | 755 |
| `/srv/soc/deploy.log` | every verification and deploy, with digests | 644 |

## Database step
When `env/db.env` and `env/db-owner.env` both exist, `deploy.sh` also starts the
`db` service, waits until it is healthy and runs the migration job with the new,
verified image **before** it swaps the api and console. If the database does not
come up or a migration fails, it puts the previous `image.env` back and stops:
nothing running has changed. With neither file it logs that it is skipping the
database; with only one of them it refuses to run. See
[database.md](database.md) for the rules this puts on migrations.

## Edge tunnel (Stage A)
The tunnel is **locally managed**: its routes come only from
`/srv/soc/tunnel/config.yml`, which is kept under version control in the private
deploy repo and checked there in CI with `cloudflared tunnel ingress validate` and
`cloudflared tunnel ingress rule`. The dashboard cannot change a locally managed
tunnel, so opening a public path takes a reviewed change. Rules:

- `/healthz` (and, when Sprint 1 ingest is ready, `/ingest/<source>`) to the public
  app, `http://api:8080`, only.
- Then the catch-all `- service: http_status:404`.
- Never the console service.

`deploy.sh` refuses to start (before changing anything) when `config.yml`, the
credentials file it names or the catch-all is missing. The account certificate
(`cert.pem`), which can manage every tunnel, never goes on the host.

```bash
cd /opt/soc-platform && git pull --ff-only
deploy/deploy.sh edge          # latest signed build from main
deploy/deploy.sh sha-1a2b3c4   # a specific build
```

## Roll back by hand
```bash
grep deployed /srv/soc/deploy.log | tail -5     # find the last good digest's tag or sha
deploy/deploy.sh sha-<previous>
```

## A deploy refuses to run
`signature verification failed` means the image was not produced by the
release workflow. **Treat that as a security event, not a glitch.** Don't
bypass it. Check the release run in Actions and the registry's package history.

## Console (tailnet only)
The operations console is served at `/console` by its own service, `console`,
which runs the same image with a different app (`soc_api.console_main`). It is
reachable **only** over the tailnet. Two layers keep the internet out:

1. The public app (`api`, port 8080) does not contain the console at all, so
   `/console` is a 404 there whatever a caller sends.
2. The `console` service runs on the host network and listens on `127.0.0.1:8081`.
   Containers, including the public tunnel, cannot connect to the host's
   loopback. `tailscale serve` on the host is the only way in, and it adds the
   caller's verified login (removing any value a client sent itself).

```bash
tailscale serve --bg http://127.0.0.1:8081     # once, on the host (was 8080 before console isolation)
tailscale serve status                         # shows the tailnet URL
```

**Moving from the single-service layout:** the first deploy of the isolated layout
makes `/console` on port 8080 disappear. Repoint `tailscale serve` to 8081 right
after the deploy (`tailscale serve reset` then the command above), or the tailnet
URL will return 404 until you do. The tunnel's readiness endpoint is now published
on `127.0.0.1:2000` for the console to read. `tailscale serve reset` clears every
serve rule on the host; check `tailscale serve status` first and re-add any others.

**Rollback across this change is partial.** The compose files come from the host's
clone, so a rollback to an image built before console isolation starts the public
app fine but the `console` service fails (that image has no `soc_api.console_main`),
and `deploy.sh` logs "rollback ALSO unhealthy". The public edge keeps serving
`/healthz`; only the console is down. Fix forward, or check out the older commit in
`/opt/soc-platform` before rolling back.

Acceptance checks on the host after a deploy (all must hold):

```bash
# On CT 110 as root: a container on the tunnel's network cannot reach the console.
# (The tunnel image has no shell, so probe with a throwaway container from the API image.)
IMG="$(grep '^SOC_API_IMAGE=' /srv/soc/env/image.env | cut -d= -f2-)"
GW="$(docker network inspect soc_default -f '{{(index .IPAM.Config 0).Gateway}}')"
docker run --rm --network soc_default --entrypoint python "$IMG" -c \
  "import socket; socket.create_connection(('$GW', 8081), timeout=3)" ; echo "rc=$? (must be non-zero)"
# From another LAN machine: neither port answers (test, do not assume).
curl -m 3 http://<CT 110 address>:8081/healthz ; curl -m 3 http://<CT 110 address>:2000/ready
# On CT 110 as root: the console answers on loopback and over the tailnet; the public edge has /healthz only.
curl -fsS http://127.0.0.1:8081/healthz
```

Host files (mode 600) read by the console service (the public app gets none):

| File | Contents |
|---|---|
| `/srv/soc/env/console.env` | **Required.** `SOC_CONSOLE_USERS=login@example.com`, the logins allowed into the console. The console refuses to start in prod without it, and `deploy.sh` stops before changing anything if it is missing. |
| `/srv/soc/env/lc.env` (optional) | `SOC_LC_OID=…` and `SOC_LC_API_KEY=…` (read-only key) for the sensor fleet panel |
| `/srv/soc/env/ingest.env` (the `api` service only, mode 600) | `SOC_INGEST_SECRETS={"<source>": ["<current>", "<next>"]}` as one line of JSON (each secret 16+ characters; a source with no entry is a 404 on the internet). Make each source name unguessable, for example `lc-` plus 16 random lowercase letters and digits: a configured source answers 401/413/415 where an unknown one answers 404, and its per-source rate limit counts unauthenticated requests too, so the name is what keeps a stranger from finding it and filling that bucket and `SOC_INGEST_DATABASE_URL=postgresql+psycopg://soc_ingest:…@<host>/<db>`. The role can only call `ingest_alert()`. Rotate by adding the new secret as `next`, changing the webhook output to it, then dropping the old one. Without this file every `/ingest/` path is a 404; with secrets but no database, deliveries get a 503 (nothing is stored, never a false 200). The edge rule for `/ingest/` is live (private deploy repo). |
