# AI SOC: Research Index

> **Status (2026-10-17):** design complete through Phase 9 plus a deferred malware-analysis phase. Nothing built yet.

## What this is
A design for a small, always-on security operations center for a one-person MSP/MSSP: detections from endpoint, network and managed-vendor sources flow into one case system, an LLM analyst triages each case, and the human acts as incident commander. It is built for the firm's own environment first, with a multi-client data model from the first table, so adding paying clients is onboarding, not redesign.

## Reading order
| Note | Topic | Build status |
|---|---|---|
| [01 Overview and Principles](01-overview-and-principles.md) | Goals, roles, architecture, vocabulary | design done |
| [02 Phase 0 Detection Tuning](02-phase-0-detection-tuning.md) | Measure and cut false positives before automating | not started |
| [03 Phase 1 Alert Path and Pager](03-phase-1-alert-path-and-pager.md) | Ingest, case store, paging, backup channel | not started |
| [04 Phase 2 Resilience and Recovery](04-phase-2-resilience-and-recovery.md) | Failure matrix, catch-up, heartbeat, backups | not started |
| [05 Phase 3-4 LLM Triage and Case Conversation](05-phase-3-4-llm-triage-and-case-conversation.md) | Per-case analyst sessions, live thread | not started |
| [06 Phase 5 Work Registry and Quiet Lane](06-phase-5-work-registry-and-quiet-lane.md) | Telling "our own work" from an intruder without suppressing | not started |
| [07 Phase 6 Network and Third-Party Sources](07-phase-6-network-and-third-party-sources.md) | Network IDS, managed-vendor lane, adapters | not started |
| [08 Phase 7 Playbooks and Automation Tiers](08-phase-7-playbooks-and-automation-tiers.md) | Containment gates, approvals, return to service | not started |
| [09 Phase 8 Multi-Client Data Model](09-phase-8-multi-client-data-model.md) | Endpoints mapped to clients, onboarding | not started |
| [10 Phase 9 Hosting and Portability](10-phase-9-hosting-and-portability.md) | Self-host first, VPS later, portable container | not started |
| [11 Phase X Malware Analysis Lab](11-phase-x-malware-analysis-lab.md) | Sandbox plus bare-metal escalation | deferred |
| [12 True Positive Response Sequence](12-true-positive-response-sequence.md) | The end-to-end incident flow | design done |
| [13 Cost Model](13-cost-model.md) | Per-case and monthly cost | estimate |
| [14 Security Design and Threat Model](14-security-design-and-threat-model.md) | Controls for a high-value target | design done |
| [15 Decision Log](15-decision-log.md) | Dated decisions and reasons | live |

## Build order at a glance
```
Phase 0 tuning baseline ─┐
Phase 1 alert path ──────┼─> Phase 2 resilience ─> Phase 3-4 triage + conversation
                         │                          └> Phase 5 work registry
Phase 6 sources ─────────┘                              └> Phase 7 playbooks
                                                            └> Phase 8 multi-client ─> Phase 9 hosting move
Phase X malware lab: independent infrastructure track, deferred
```
