# Phase 0: Detection Tuning Baseline

## Why first
Detection rules were sound; the operator's daily work (file-structure changes, security testing, an LLM agent running shell commands) trips them constantly. A pager that cries wolf gets ignored. Automation built on noisy input amplifies the noise. So measure first.

## Method
1. **Export** detections for a representative window.
2. **Cluster** into incidents (same sensor, gap under ten minutes) and **dedupe** by rule within an hour.
3. **Attribute** every detection to a cause: operator task, agent shell session, scheduled system job, or unexplained.
4. **Classify each rule:** (a) fix inside the rule, (b) gate by lineage and registered work, (c) leave alone.
5. **Re-measure** after each change.

## Baseline from the first week (one Linux sensor, build-heavy week)
- 59 detections, 18 time clusters, 25 incidents after a 60-minute same-rule dedupe.
- 51 of 59 traced to the operator's own work: firewall rule work 15, agent shell sessions 14, an SSH hardening change 14, hourly boot-hook noise 8.
- 8 unexplained in a first pass, mostly recon-burst hits. These are the best test cases for the work registry because the registry must recognize routine work and still catch the odd one.
- 15 hits from one scheduled system job calling a harmless architecture check: fixed by an exact-command exclusion in the rule; no repeats afterward.

## Fix patterns
| Pattern | Use when | Example |
|---|---|---|
| Exact-command exclusion in the rule | A narrow, machine-generated benign trigger | Ignore one exact architecture-check command inside a recon-burst rule |
| Lineage gate (quiet lane) | Admin work that legitimately looks like an attack | Persistence edits, sudo changes, file-integrity hits during registered sessions |
| Leave alone | Behavior that should always be visible | Reverse-shell pattern with no matching session |
| Gate the response, not the detection | A rule's response action is too aggressive | Single file-integrity hit that isolates a host; require two signals instead |

**Portability principle:** fixes live in the rule itself, not in a separate false-positive rule, so the rule pack can be shared and reused unchanged.

## A lesson worth keeping
A rule that isolates the host on one file-integrity hit isolated the operator's own workstation several times during a hardening session. The rule was right to alert and wrong to contain on a single signal. Containment moves behind the stacked-evidence gate.

## Output
A per-rule table: benign pattern observed, fix type, projected reduction in pages, and status. Re-run weekly until the page rate is low enough to trust.

## Acceptance
- Page-lane volume on normal operator days drops by an agreed target (start at 70%).
- No rule loses coverage of a recorded true-positive test.
- Every change is reviewed by a human before deployment.
