# Phase 8: Multi-Client Data Model and Onboarding

## Principle
Everything hangs off `client`. The first tenant is the firm itself; the schema never assumes one.

## Tables (generic)
| Table | Key fields | Notes |
|---|---|---|
| `client` | id, slug, name, tenant id (detection platform), status (internal / pilot / paying), tier, timezone, contacts, escalation policy, auto-response allowed, retention days, vendor account id | pricing is never stored here |
| `site` | id, client id, name, network-controller site id | a client can have several sites |
| `endpoint` | id, client id, site id, sensor id, hostname, platform, tags, role, criticality, owner, auto-response allowed, enrolled at, last seen | sensor id is the join key to the detection platform |
| `source` | id, client id, type, external id, secret reference, enabled | how an event is attributed; secrets are references, never values |
| `alert` | normalized fields, case id, verdict | one row per source event |
| `case` | id, client id, severity, status, verdict, lane, opened, closed, closing note | grouping: client + endpoint + rule family + window |
| `case_event` | case id, time, actor, kind, body | append-only audit |
| `activity_session` | id, client id, endpoints, actor, purpose, start, end, lineage hints | the work registry |
| `action` | id, case id, tier, type, target, status, approved by | includes would-have-done |
| `runbook` | rule, scope (global or client), steps, match config | per-rule triage guide |
| `notification` | case id, channel, sent, acked, attempts | the outbox |
| `usage` | client id, month, alerts, cases, tokens in/out, cost | per-client metering |
| `user` | id, role, contacts | roles exist so a second analyst or a client read-only view is not a rewrite |

## Attribution
See Phase 1 for the ordered rules. Unmapped events land in Unassigned and block automation until mapped.

## Isolation between clients
Per-client read-only and scoped-response keys, per-client model sessions, per-client spend caps and retention. Cross-client correlation (the same indicator across clients) is a separate, deliberate feature that is off by default and uses only hashed or defanged indicators.

## Onboarding checklist (repeat per client)
1. Contract language covering monitoring, data handling, AI-assisted analysis, containment authorization, retention.
2. Create the tenant (or tag scheme), per-site install keys, enroll endpoints, record sensor ids.
3. Create client, site, endpoint and source rows.
4. Set escalation policy, auto-response permissions, and the client's spend cap.
5. Create the client's read-only and scoped-response keys in the secrets manager.
6. Import the baseline rule pack in report-only mode.
7. Two-week baseline before any automation is enabled.
8. Confirm contacts and an out-of-band way to reach them during an incident.

## Metering
Usage per client feeds both cost control and pricing decisions. Prices come from the firm's rate card, not from this design.

## Acceptance
- A test client with two endpoints produces cases that never appear in another client's views, keys or model context.
- An unknown tenant id lands in Unassigned.
- Per-client usage totals match provider usage.
