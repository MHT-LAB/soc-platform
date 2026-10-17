# Phase 0: detection tuning baseline

Ten days of detections from the first enrolled workstation, sorted by cause
before any paging or automation exists. Method: [design note 02](../design/02-phase-0-detection-tuning.md).

## Headline
| Measure | Value |
|---|---|
| Detections | 60 |
| Time clusters (same sensor, gap < 10 min) | 19 |
| After 60-minute same-rule dedupe | 26 |
| Attributed to an intruder | **0** |
| Still unexplained | **0** (the 8 open after the first pass are now explained) |
| Removed by rule fixes alone | 31 of 60 (52%) |
| Left for the work registry (correct rules, operator's own work) | 29 |

## By rule
| Rule family | Source | n | Cause | Fix |
|---|---|---|---|---|
| Host firewall disabled | managed pack | 15 | The host firewall flushes and rebuilds its own chains on every rule change and reload (14 in 5 seconds; a full reload flushes ~40 chains twice) | False-positive exception: root flushing a single firewall-owned chain, nothing else on the line. Opening the firewall (`-F INPUT`, flush-all, `-P ACCEPT`), chained commands, impostor binaries and non-root still fire. Managed rules can't be edited, so an exception is the only option |
| Recon burst | custom | 15 | Hourly boot-snapshot hook calling an architecture check (8); interactive admin sessions (7) | Exact-command exclusion in the rule (shipped, verified: no repeats since); lineage gate for the rest |
| Canary file touched + file integrity hit | custom | 7 + 7 | One SSH-hardening session. Each file-integrity event fired **two** rules | Isolation removed from the Linux branch; the duplicate rule is retired |
| Reverse shell | custom | 4 | The operator's AI agent probing a service port with `/dev/tcp`; a simulation | **Leave alone.** Must stay visible; lineage gate only |
| Pipe to shell, persistence, scanner, sudo, exec from temp | custom | 11 | Agent shell sessions, field-kit network scans, rule simulations | Leave alone; lineage gate |
| Pipeline test | custom | 1 | Synthetic end-to-end test | Test lane, never pages |

## What this taught
1. **The AI agent's shell is the biggest trigger family.** Its command wrappers contain attack-looking strings, and its real actions (port checks, config reads) look like recon. This is the case for matching registered work on **process lineage** rather than time windows: the agent's work is recognizable by where it comes from, and an intruder working during the same hours is not.
2. **A rule can fire on wrapper text, not behavior.** One reverse-shell hit came from a wrapper whose command line only *contained* `/dev/tcp`. Alerting was correct; the lineage gate must separate "string present" from "connection opened."
3. **Duplicate rules double the pages.** One file-integrity event produced two detections. Ingest dedupes by source event as well as by rule.
4. **Managed rule packs need their own baseline.** A subscribed pack produced a quarter of all detections and can only be tuned with exceptions.

## Acceptance (from the design)
- Page-lane volume on a normal operator day down by **70%**: rule fixes reach 52%; the work registry carries the rest. Until it ships, paging is limited by dedupe and severity.
- No rule loses coverage of a recorded true-positive test: none of the fixes touch the reverse-shell, pipe-to-shell, scanner or persistence rules.
- Every live change is approved by the owner before deployment.

## Correction: the first exception was too narrow
The first version excepted four chain names seen in the baseline. A live reload
then flushed about forty firewall-owned chains and produced 50+ detections.
The first "zero detections" check had run a minute after the reload, before
the platform had indexed them. Two fixes: the exception now matches any single
firewall-owned chain (tested against attack cases that must still fire), and
every "no detections" check now waits five minutes. Re-test: the reload ran,
zero detections.
