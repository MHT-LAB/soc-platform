# soc-platform

An AI-assisted security operations center that a small MSSP can afford to run.

Every alert from endpoint, network and managed-vendor sources becomes one case
in one console. An LLM analyst triages each case: whether it's the operator's
own work, the indicators, related activity, ATT&CK mapping, and a short brief.
A human incident commander gets paged immediately and makes the calls.

> **Status:** Sprint 0, foundations. The pipeline, repo controls and a
> health-check service are in place; no security data flows yet.
> Twelve one-week sprints; progress is logged in [`docs/sprint-reviews/`](docs/sprint-reviews/README.md).

## Principles the code enforces

1. **Page first, analyze second.** A model outage can delay a brief, never a page.
2. **Annotate, never suppress.** Known admin work is quieted and logged, never deleted or contained.
3. **Match the actor, not the clock.** Process lineage and user, not time windows.
4. **Evidence gates are code.** The model proposes, a deterministic function decides, a human approves.
5. **Failure becomes delay, never loss.** Catch-up from the source of truth after any outage.
6. **Client data never mixes.** Row-level security, per-client keys and model sessions.
7. **No "clean" verdict.** Malicious, suspicious, no evidence found, or not analyzed.

## Architecture

```
Sources -> adapters -> normalized alert -> ingest API
   endpoint EDR/SIEM (per-client tenant)      | verify, map to client, dedupe
   network IDS/IPS via syslog adapter         v
   managed-vendor webhook (read-only)   case store -- outbox -- page (push) + email backup
                                               |
                                 +-------------+--------------+
                           reconcile worker  triage worker  playbook executor
                           (catch-up poll)   (LLM, scoped)  (allowlisted actions)
                                               |
                                     console + live case thread
```

Full design: [`docs/design/`](docs/design/README.md) · Decisions: [`docs/adr/`](docs/adr/README.md)

## Repository layout

| Path | What |
|---|---|
| `api/` | FastAPI service: ingest, cases, console API |
| `web/` | Console (Sprint 3) |
| `detections/` | Detection rules as code with test events (Sprint 4) |
| `fixtures/` | Synthetic, identifier-free alert sets and the demo tenant |
| `deploy/` | Compose files and the deploy script |
| `docs/` | Design, ADRs, threat model, runbooks, sprint reviews |
| `scripts/` | Repo tooling, including the scrub gate |

## Quick start

```bash
make setup     # uv sync + pre-commit hooks
make test      # unit tests, warnings are errors
make lint      # ruff, strict mypy, hadolint
make up        # run the stack locally with Docker
curl -s localhost:8080/healthz
```

## Security pipeline

| Stage | Controls |
|---|---|
| Commit | gitleaks, ruff, hadolint, scrub gate |
| Pull request | tests, strict typing, Semgrep, pip-audit, Checkov, Trivy image scan, smoke test, scrub gate |
| Release | SBOM (Syft), cosign keyless signing, SBOM attestation, GHCR |
| Deploy | signature verified before run, health check, rollback |
| Runtime | non-root, read-only filesystem, no Linux capabilities, loopback-only port |

Report vulnerabilities privately: see [SECURITY.md](SECURITY.md).

All examples and screenshots use a synthetic demo tenant.
