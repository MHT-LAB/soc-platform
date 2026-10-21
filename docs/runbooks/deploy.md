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
| `/srv/soc/env/tunnel.env` | `TUNNEL_TOKEN=…` from the secrets manager | 600 |
| `/srv/soc/env/image.env` | the verified image digest, written by `deploy.sh` | 600 |
| `/srv/soc/deploy.log` | every verification and deploy, with digests | 644 |

## Deploy
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
on `127.0.0.1:2000` for the console to read.

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
