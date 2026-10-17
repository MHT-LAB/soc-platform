# True Positive Response Sequence

How a confirmed or likely true positive is handled, from detection to lessons learned. Phases follow the standard incident-response lifecycle (detection and analysis, containment, eradication and recovery, post-incident).

```mermaid
flowchart TD
  A[Rule fires or IDS event] --> B[Ingest: map to client, dedupe]
  B --> C[Page: push + email, under 10 s]
  B --> D[LLM triage: registry match, IOCs, pivots, ATT&CK, brief]
  D --> G1{Matches registered work?}
  G1 -- yes --> Q[Quiet lane: logged, in digest, never contained]
  G1 -- no or partial --> E[Commander reads brief, declares or closes]
  C --> E
  E --> G2{2+ independent signals?}
  G2 -- yes, and client authorized --> I[Isolate endpoint, rejoin ready]
  G2 -- no --> AP[Commander approves with one tap]
  AP --> I
  I --> N[Notify client contact; insurer or counsel if required]
  I --> EV[Preserve evidence: memory, artifacts, hashes, custody]
  EV --> SC[Scope: same indicators across sensors and network; cross-link vendor cases]
  SC --> ER[Eradicate or rebuild; rotate credentials]
  ER --> G3{Return-to-service checklist signed?}
  G3 -- gaps --> ER
  G3 -- yes --> R[Release, observation window]
  R --> RP[Reports for insurer or counsel, human-signed]
  R --> L[Lessons: rule changes, runbook updates]
```

## Phases and proposed targets
| Phase | Elapsed | Targets (proposals to tune against real cases) |
|---|---|---|
| 1 Detect | 0 to 1 min | page delivered under 10 s |
| 2 Triage | 1 to 15 min | acknowledged within 5 min for high/critical (re-page every 10 min); brief in the case under 5 min; incident declared or closed under 15 min |
| 3 Contain | 15 to 60 min | isolation automatic on stacked evidence, else on approval; client told right after |
| 4 Eradicate and recover | hours to days | evidence collected before any wipe; release only with the signed checklist |
| 5 Learn | days to weeks | reports reviewed and signed; rule and runbook changes shipped |

## The four decisions
1. **Ours?** Actor and lineage match registered work. Match: log and stop. Partial or none: continue.
2. **2+ signals?** Independent signals agree, or a clear active-exploitation pattern.
3. **Client authorization.** Isolation of a client endpoint requires prior contractual authorization; otherwise it is always the commander's call after a phone call.
4. **Signed?** Return to service only after the checklist is signed.

## Record keeping
Every tool call, message, approval and action goes to the append-only case log. Evidence has hashes and chain of custody. External reports tag findings observed, inferred or unverified and state limitations. The system never drafts admissions of fault, refunds or insurance offers; those come from the human.
