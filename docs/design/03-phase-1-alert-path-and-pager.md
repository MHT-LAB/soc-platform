# Phase 1: Alert Path and Pager

## Goal
A real detection reaches the phone, creates a case, and also sends an email, with no LLM involved yet.

## Components
- **Ingest API** behind a stable public hostname. Per-source secret or HMAC, rate limit, body-size cap, vendor IP allowlists where published.
- **Case store** with migrations from day one (SQLite for the first tenant, Postgres when the second client lands).
- **Outbox.** Pages are rows. A worker retries until acknowledged or escalated. Nothing is sent fire-and-forget.
- **Pager:** push notification (click URL opens the case) with an independent email path.
- **Minimal console:** case queue and case detail.

## Normalization
Every adapter maps its event to one shape (see overview). Idempotency key is the source's own event id, so redelivery never duplicates a case.

## Client attribution (first hit wins)
1. Tenant identifier in the webhook → source record → client.
2. Sensor id → endpoint → client and site.
3. Sensor tag convention for clients sharing a tenant.
4. Network syslog source address or site id → site → client.
5. Managed-vendor account id → client.
6. **Unmapped events are never dropped:** they land in an Unassigned queue, page at medium severity, and block auto-actions until mapped.

## Build steps
1. Container, container runtime, mesh VPN access, tunnel to the public hostname.
2. Compose stack, database, first client/site/endpoint/source rows.
3. Ingest endpoint with normalization, secret check, mapping, idempotent insert.
4. Outbox worker: push and email.
5. Source webhook pointed at ingest (detections only, start with one rule family).
6. Minimal console.

## Acceptance tests
- Harmless simulation fires → case appears, phone buzzes, link opens the case, email also arrives.
- Stop the service → email still arrives; restart → catch-up creates the case with no duplicates.
- Replay the same webhook twice → exactly one case.
- Event with an unknown tenant → lands in Unassigned and pages.

## Risks
Webhook retry behavior varies by vendor and must be verified. The first build must prove the independent email path works without the service running.
