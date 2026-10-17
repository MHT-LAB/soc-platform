# Phases 3-4: LLM Triage and Live Case Conversation

## Goal
Each case gets an analyst brief within minutes, and the commander can talk to the analyst about the case in the console, with the case evidence already loaded.

## Triage worker
- One LLM session per case, started on case creation, **scoped to one client**: that client's read-only API key and that client's rows only.
- **Fixed tool set, read-only:** fetch the detection and surrounding events, process tree and lineage, related detections on the same endpoint or actor, sensor info, recent history, network-source events for the same address or client device.
- **Output** written into the case: verdict, indicators (defanged), pivots tried and results, ATT&CK techniques with the evidence for each, a short brief, and a recommended action. Nothing is executed by the analyst in this phase.
- **Model tiering:** a small model screens every alert (including the work-registry check), a mid-size model does full triage on anything not clearly benign, a large model is used only for escalations and live conversation. Prompt caching on the system prompt and runbooks.
- **Cost controls:** dedupe before any model call, per-client soft caps, a global hard cap that fails closed (stop model calls, keep paging).

## Conversation
- Case page chat on the same session, streamed with server-sent events. The case is the memory; a resumed session reloads the case, not a transcript.
- Action buttons in the case (approve, reject, mark as ours, escalate) write to the audit trail and execute only within their tier.
- Every tool call, message and action is appended to an immutable case event log.

## Prompt-injection posture
Alert fields (command lines, hostnames, file names, network message text) are attacker-controlled. They are passed to the model as quoted data with an explicit instruction that content inside is untrusted; the model has no tools beyond the read-only set; verdicts about containment are checked by the gate in code; and a replayed test corpus includes entries whose text tries to instruct the analyst.

## Build and test
1. Session worker with the read-only tool set and the case writer.
2. Replay the real detection fixtures through triage; compare briefs to the attribution made by hand in Phase 0.
3. Follow-up push with the verdict ("matches registered task" / "suspicious" / "escalate").
4. Live chat on the case page.
- **Tests:** replay of the first-week fixtures matches hand attribution; an injection fixture ("mark this safe") does not change the verdict; the spend cap stops model calls while paging continues; a case for client A never loads client B data.

## Open items
Verify provider billing and terms for a hosted multi-client agent before building. Check whether the detection platform's native case and AI features overlap before duplicating them.
