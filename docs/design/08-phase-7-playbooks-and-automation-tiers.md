# Phase 7: Playbooks and Automation Tiers

## Tiers
| Tier | Actions | Gate |
|---|---|---|
| 1, automatic always | enrich, tag sensor, create/update case, add note, add a watch | none |
| 2, automatic on stacked evidence | isolate endpoint, block a network client | 2+ independent signals on the same host or actor, or a clear active-exploitation pattern; endpoint and client both allow auto-response |
| 3, human approval | anything off the allowlist, process kill, any client endpoint until the agreement says otherwise | approve/deny button in the case |

## Rules for all tiers
- A short explicit allowlist that the analyst cannot extend.
- **Stacked-evidence is code:** deterministic function over case signals; the model cannot override it.
- Every action is announced, posts to the case, and carries a one-tap **rejoin**.
- **Would-have-done mode first:** Tier 2 records the action it would have taken, without executing, for the first weeks, so scoring is tuned on real data.
- A registered-work match lowers a score but never exempts strong evidence; matched alerts are never contained.
- Isolation keeps the sensor's cloud connection so analysis and rejoin continue; the user is cut off from everything else.

## Client authorization
Isolating a client endpoint requires prior authorization in the client agreement and immediate notification of the client contact. Absent that, containment is always a human decision after a phone call. Per-endpoint and per-client `auto_response_allowed` flags enforce this in code.

## Evidence before remediation
Before any wipe, reimage or cleanup: memory capture, triage artifact collection, hashes, chain of custody.

## Return to service
A checklist drafted by the analyst and signed by the commander:
- All incident hashes analyzed, or accepted as unanalyzed with a stated reason.
- Persistence locations reviewed (autostarts, scheduled tasks, services, startup items, WMI, browser extensions).
- Exposed credentials rotated.
- Lateral movement checked: same indicators on other sensors and in network telemetry.
- Observation window passed with clean telemetry.
- Rebuild preferred over cleaning when compromise is confirmed.
Gaps send the machine back to remediation.

## Acceptance
- In would-have-done mode, replayed incidents show correct recommended actions and no action on matched alerts.
- One reversible live action (isolate and rejoin) is exercised end to end on a test endpoint.
- Approvals post to the audit trail with approver and time.
