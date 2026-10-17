# Phase 5: Work Registry and the Quiet Lane

## Problem
The operator does admin and security work all day, on the same machines being monitored, through an LLM agent that runs shell commands. The same behaviors that define an attack (reverse-shell tests, persistence edits, scanner use, firewall changes) are routine here.

## Mechanism
1. **Register work.** A `work start "<purpose>" <duration>` command, plus a hook that registers each agent session automatically, writes a session record: client, endpoint(s), actor, purpose, start, end, lineage hints. The monitored endpoint also receives a time-limited tag.
2. **Match per alert** on three things: the actor (user id), the process lineage (ancestor executable path and hash, not only a command-line string), and the registered window.
3. **Outcome:**
   - **Matched** (actor and lineage agree): quiet lane. Logged, in the daily digest, no page, no containment.
   - **Partial** (the time fits, the lineage does not): this is the interesting case. It pages at reduced severity.
   - **Unmatched:** full pipeline.

## Why lineage, not command line
A process's command-line text can be reproduced by anything that can launch a process. Executable path, hash and user id are harder to spoof. Which parent fields the endpoint sensor reports must be verified before the match depends on them; if the sensor exposes only command text, add a dedicated user id for agent activity.

## Never
- Never delete a matched alert.
- Never contain on a matched alert.
- Never extend the registry from model output; sessions are created by the operator or the hook only.

## Test corpus
Use the first-week detections: attributed ones must land matched, and the unexplained ones must come out partial or unmatched. Add a fixture where an unrelated process reproduces a registered command line and confirm it does not match.

## Acceptance
- Quiet-lane share on normal operator days is high (target above 80%) with zero matched alerts later found malicious in replay.
- Partial matches are rare enough to read every one.
