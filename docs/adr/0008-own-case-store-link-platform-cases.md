# 0008: Own case store; link the EDR platform's cases for investigations

**Status:** accepted · **Date:** 2026-10-17 · Resolves the open item in design note 05.

## Context
The EDR platform (LimaCharlie) offers a cases extension: case lifecycle and
status, severity and SLA tracking, notes and time logging, linked detections,
entities, telemetry and artifacts, merging, reports, and a multi-org
dashboard. It was unused in the first tenant at the time of this decision
(zero cases). The design calls for one case system across every source. The
question was whether to build that store or adopt the platform's.

## Options
| | Platform cases only | Own store only | **Own store + link platform cases** |
|---|---|---|---|
| Cases from network IDS, MDR vendor, future sources | Only what is routed into the platform | Yes | Yes |
| Quiet lane, work registry, evidence gates, automation tiers | Would live outside the case anyway | Native | Native |
| Paging outbox and delivery audit | No | Native | Native |
| Per-client isolation and cost metering | Per org | Row-level security, per-client usage | Same |
| Investigation pivots into raw telemetry, entities, artifacts | Native and rich | Must be rebuilt | **Native, via the linked case** |
| Lock-in | High | None | Low: the link is optional |
| Build cost | Lowest | Highest | Medium |

## Decision
This project's Postgres case store is the **system of record** for every
alert, case, lane, action, approval and page, across all sources and clients.

When a case is **declared an incident** (or the commander asks for it), the
SOC creates a **linked platform case** for that client's org and stores its
id on the SOC case. Investigation artifacts (entities, telemetry, artifacts)
are gathered there, where the platform's tooling is strongest, and the SOC
case shows a link and a status summary. The link is one-directional and
optional: the SOC never depends on it to page, triage or act.

## Consequences
- The quiet lane, registry and gates (the parts that make this design
  different) stay in code we control and test.
- Investigations get the platform's mature pivoting without rebuilding it.
- Linking needs a separately scoped key with case permissions (not the
  read-only fleet key). Add it with the incident workflow (Sprint 6 or 9).
- Verify the extension's pricing and quotas before enabling linking for
  paying clients.
- If a client has no platform tenant (vendor-only sources), cases simply
  have no link.
