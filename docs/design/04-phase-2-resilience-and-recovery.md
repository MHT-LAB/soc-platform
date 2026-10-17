# Phase 2: Resilience and Recovery

## Design goal
Every failure becomes a delay, not a lost alert, and the human learns when the SOC itself is degraded.

## Failure and delay matrix
| Failure | Effect | Detected by | Mitigation and recovery |
|---|---|---|---|
| Site power loss | Console and tunnel down; cloud detection continues | External uptime monitor; email path still delivers | Battery backup for host, modem, router; catch-up on return |
| ISP outage | Same; on-site sensors also offline | External monitor; sensor-offline detections | Mobile hotspot for the operator; catch-up on return; later move to a VPS |
| Hypervisor host down | All containers down | External monitor | Auto-start on boot; catch-up |
| Service container down | Console and service-side pages stop | Healthcheck, restart policy, external monitor | Restart policy; nightly backups; email path continues |
| Tunnel or CDN outage | Webhooks cannot reach the service | Vendor failure counters; external monitor | Reconcile worker polls the source directly, so webhooks are an optimization, not the only path |
| Missed or dropped webhook | Missed alert | Reconcile compares source to local table | Poll with a per-tenant cursor; idempotent insert on source event id |
| Duplicate delivery | Repeat pages | n/a | Idempotent insert; page dedupe window |
| LLM provider outage or rate limit | No briefs | Worker error counters | Page already sent; cases wait in triaging; retry with backoff; digest notes the gap |
| Spend cap reached | Triage stops | Usage meter | Fail closed: stop model calls, keep paging, notify |
| Push provider outage | Push fails | Outbox shows unacked pages | Email backup after a timeout of no acknowledgement |
| Mail path failure | Backup fails | Outbox | Push remains primary; review the mail path monthly |
| Database corruption or full disk | Service errors | Healthcheck, disk alert | Nightly consistent backups; restore, then catch-up rebuilds cases from the source |
| Model wrong or manipulated | Bad verdict | Case audit trail | Evidence gate in code, read-only keys, tiers, no autonomous action beyond the allowlist |
| Operator unreachable | Page unacked | Outbox | Re-page every 10 minutes for high/critical, then email; optional second commander |

## Standing mechanisms
- **Outbox pattern** for every notification.
- **Reconcile worker:** every few minutes per tenant, fetch detections since the cursor and insert any missing; full catch-up on startup.
- **Heartbeat:** a synthetic detection every few hours proves the whole chain; silence pages by the independent channel.
- **External monitor:** a hosted uptime check on a health endpoint, not hosted at the same site.
- **Degraded banner** in the console during catch-up or model outage.
- **Backups:** nightly consistent database copy; pulled by the storage side so the service holds no credentials to the firm's internal storage; encrypted offsite copy as the second copy; container backup. Restore drill: rebuild the database from backup plus catch-up on a throwaway instance.

## Acceptance
- Kill the service mid-incident; page still arrives by email; restart backfills with no duplicates.
- Cut the tunnel for an hour; reconcile fills the gap.
- Restore drill completes and cases match the source.
