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
