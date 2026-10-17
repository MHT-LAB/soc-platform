# AI SOC: Overview and Principles

## Goal
Every security alert from every source becomes a case in one console. An LLM analyst triages each case: is this our own work, what are the indicators, what else is related, how does it map to ATT&CK, what is the brief. The human incident commander is paged immediately, opens the case from the notification, and works it in a live conversation with the analyst. High-confidence incidents with stacked evidence trigger containment automatically; everything else waits for a human tap.

## Roles
| Role | Does |
|---|---|
| LLM analyst (Tier 1/2) | Triage, indicator extraction, pivots, ATT&CK mapping, briefs, tracking, allowlisted playbooks |
| Incident commander (human) | Gets paged, decides, approves high-risk actions, owns escalation policy, signs release and external reports |
| Managed MDR vendor (where used) | Handles its own incidents end to end; displayed read-only; never triaged or acted on by the analyst |

## Principles
1. **Page first, analyze second.** Notification goes out before any LLM call. A model outage can delay a brief, never a page.
2. **Annotate, never suppress.** "This is our own work" downgrades and quiets an alert; it never deletes it and never allows containment.
3. **Match on the actor, not the clock.** Time windows alone let an attacker hide inside the operator's working hours.
4. **Evidence gates are code, not opinion.** Whether two independent signals agree is computed deterministically; the model proposes, code decides, a human approves above the allowlist.
5. **Failure becomes delay, never loss.** Every component can fail; the system catches up from the source of truth afterward and tells the human it is degraded.
6. **Client data never mixes.** Separate keys, separate rows, separate model contexts per client.
7. **No "clean".** Analysis verdicts are malicious, suspicious, no evidence found, or not analyzed, always with a coverage statement.
8. **Evidence before remediation.** Collect and hash before any wipe, reimage or cleanup.
9. **Tune before you automate.** False positives are the binding constraint; the work registry and quiet lane carry the load while rules are tuned.

## Architecture
```
Sources -> adapters -> normalized alert -> ingest API
   endpoint EDR/SIEM (per-client tenant)      │ verify, map to client, dedupe (idempotent)
   network IDS/IPS via syslog adapter         ▼
   managed-vendor webhook (read-only)   case store ── outbox ── page (push) + email backup
   other adapters later                        │
                                    ┌──────────┼───────────────┐
                              reconcile worker  triage worker   playbook executor
                              (catch-up poll)   (LLM, scoped)   (allowlisted actions)
                                                │
                                          console + live case thread
```
Normalized alert: `alert_id (source id, idempotency key), client_id, site_id, endpoint_id, source, severity, rule, summary, actor, lineage, mitre_hint, raw, received_at, detected_at`.

## Vocabulary
- **Case:** a group of related alerts for one client and endpoint within a window.
- **Lane:** page (human attention), quiet (logged, in digest), vendor (read-only).
- **Work registry:** record of the operator's own activity sessions, used for lineage matching.
- **Tier 1/2/3:** automatic always / automatic on stacked evidence / human approval.
- **Quiet lane:** matched-to-registered-work alerts: logged, digested, never paged, never contained.
- **Would-have-done mode:** Tier 2 actions recorded but not executed, used for the first weeks.

## Why this is a good project
It is useful the day it works (one person covering several environments), it produces a real portfolio artifact (design, data model, failure analysis, cost model, and measured tuning results), and every phase ships value on its own.
