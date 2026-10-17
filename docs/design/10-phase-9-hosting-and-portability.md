# Phase 9: Hosting and Portability

## Staged hosting
- **Stage A (first tenant only):** a dedicated container on the firm's own hypervisor. Near-zero incremental cost; acceptable while only the firm's own environment depends on it.
- **Stage B (trigger: a paying client's endpoints feed the SOC, or any promised response time):** a small VPS (about 2 GB RAM). The move takes about 30 minutes because the system is built portable from the start.

## Why staged
A self-hosted SOC on the firm's own premises has a longer dependency chain (power, ISP, hypervisor, container, tunnel). At 99.99% availability a year still allows about 52 minutes of downtime, and real business and residential links rarely reach it. The failures also correlate with the incidents a SOC exists for. Stage A is acceptable only because the resilience design (independent email path, catch-up worker, external monitor) turns outages into delays. Once clients depend on it, "our site lost power" stops being an acceptable answer.

## Portable container design
- One repository, one compose file. Services: application (ingest, console, workers; split into api and worker if volume requires), database (file-based first, Postgres container later), edge (tunnel in Stage A, reverse proxy in Stage B). Swapping the edge service is the only compose change at migration.
- **All state in one directory**, mounted into containers. No other host paths, no host-specific networking assumptions.
- **Configuration by environment and secret files only.** No secrets in the image, repository or compose file; secrets come from a secrets manager at deploy time into mode-600 files outside the repository.
- **Versioned images:** pinned base, tagged by commit and semantic version, last three tags kept for rollback. Non-root user, read-only root filesystem where possible, dropped capabilities, healthchecks on every service.
- **Stable public hostname on the firm's own domain** from day one. Stage A: record points to the tunnel. Stage B: record points to the VPS. Vendor webhooks never change.
- Development and production run the same compose with a test client and replayed sample alerts.

## Migration runbook (A to B)
1. Announce maintenance.
2. Stop the application; take a final consistent database backup.
3. Copy the state directory to the VPS; bring up compose there.
4. Run catch-up to pull anything missed.
5. Switch DNS; watch healthchecks and the next heartbeat.
6. Keep Stage A stopped but intact for seven days.
Rehearse once on a throwaway instance before it is needed.

## Stage A specifics
Dedicated unprivileged container with container-runtime support enabled, about 2 vCPU and 2-3 GB RAM, firewall limited to the few egress destinations needed, console reachable only over the mesh VPN, no inbound port forwards, backups pulled by the storage side, battery backup on host, modem and router.

## Candidate VPS notes (recheck before the move)
Entry plans from the large general-purpose providers sit at roughly $5-6 for 1 GB and about $12 for 2 GB. Free-tier offers with idle reclaim are unsuitable for an always-on SOC. Prices moved more than once in 2026; verify at decision time.

## Acceptance
- Full restore on a clean machine from the repository and one state directory.
- Migration rehearsal completes inside the target window with no lost alerts.
