# Decision Log

Dated decisions with reasons. Newest first.

| Date | Decision | Reason |
|---|---|---|
| 2026-10-17 | Malware analysis lab deferred; the SOC comes first | Independent track; the SOC delivers value sooner |
| 2026-10-17 | Malware detonation on a dedicated donor machine in addition to a VM sandbox | Defeats VM-aware malware; avoids contaminating a machine used for client-facing work |
| 2026-10-17 | Verdict vocabulary has no "clean" | A wrong "clean" is the most expensive error |
| 2026-10-17 | Quarantine by isolation is the default for suspect client machines; release needs a signed checklist | Cost of a false release exceeds cost of a delayed one |
| 2026-10-17 | Tune detection rules over time; do not loosen them to cut noise | Rules are sound; the noise is the operator's own work, handled by the registry |
| 2026-10-17 | Hosting staged: dedicated container first, VPS at the first paying client | Saves cost now; the move is a data copy because the system is portable |
| 2026-10-17 | Multi-client data model from the first table | Adding clients becomes onboarding, not redesign |
| 2026-10-17 | Work registry matches actor and lineage; annotates, never suppresses | Time windows alone hide attackers inside working hours |
| 2026-10-17 | Auto-containment only on stacked evidence; would-have-done mode first | One signal cannot be trusted to isolate a host |
| 2026-10-17 | Managed MDR vendor incidents are read-only in the console | The vendor's human analysts own that response |
| 2026-10-17 | Push notification first, email as independent backup | The backup must not depend on the SOC service being up |
| 2026-10-17 | Reconcile worker polls the source in addition to webhooks | Webhooks become an optimization; outages become delays |
| 2026-10-17 | Notes written without private identifiers from the start | Publishing later is curation, not a rewrite |
