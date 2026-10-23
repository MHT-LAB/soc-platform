# Hardening reference

A checklist of the controls this project relies on, written as actions to take and why. It describes the approach, not any particular deployment: no hosts, addresses, identifiers or settings values belong here, and it is not a record of the current state.

## Source and review
- Protect the main branch: pull requests only, signed commits, linear history, required checks, no force-push, no bypass. *Why: every change gets a reviewer of record, and history can't be rewritten.*
- Check the text that will become the commit message (PR title and body) as well as the files. *Why: squash merging publishes it.*
- Scan the added lines of every commit in a PR, not only the final tree. *Why: a value added and removed within one PR still lives in history.*
- Make checks fail closed. Judge scans by their output, not their exit status, and fail when a required input (such as a denylist) is missing. *Why: a gate that passes when it can't run is not a gate.* Test the gate itself by planting each failure it should catch.

## Build and release
- Pin every CI action by full commit SHA and require pinning in repository settings. *Why: a moved tag can't change what runs.*
- Keep workflow tokens read-only by default and grant permissions per job.
- Restrict who can create, move or delete release tags, and require release builds to come from reviewed code.
- Scan the pushed image before signing it, sign it keylessly, and attach an SBOM. *Why: an image that fails the scan is never signed, so it can't be deployed.*

## Deploy
- Deploy by digest, never by mutable tag, after verifying the signature, who signed it, and that the signing commit is on the main branch.
- Refuse to deploy from an edited or out-of-date checkout. Refuse before changing anything, and keep a rollback.
- Refuse to start without required secrets or an access list, instead of defaulting to open.
- Keep test-only switches from working for the privileged user.

## Network and exposure
- Expose the minimum to the internet: one narrow path set, everything else a fixed 404, with the allowed paths kept as reviewed code rather than edited in a dashboard.
- Run the admin interface as a separate application and a separate service from the public one, reachable only over a private network. *Why: a misrouted request can't reach code that isn't there.*
- Never treat an identity header as proof unless the only path to the service is the proxy that sets it and strips client values.
- Bind services to loopback unless something needs them, and test reachability from the places an attacker would stand, not just from the host.

## Public ingest endpoints
- Authenticate every sender with a per-source secret or signature checked over the raw body, in constant time, before parsing.
- Cap the body while reading it, rate limit by the real client address, and make unknown routes and unknown sources look identical.
- Make inserts idempotent, so replays do nothing. Return an error, not success, when something couldn't be stored.
- Keep secrets, bodies and headers out of logs. Give the public service only the credentials it needs.

## Data and AI
- Treat all alert fields as untrusted text. The model proposes; code decides. Keep tools read-only by default, and gate any action in code.
- Enforce client separation in the database, not only in application code.

## Operations
- Keep secrets out of the repository, image and notes; deliver them as restricted files.
- Watch the system itself: heartbeat, external uptime check, and a second alert channel.
- Log every host change in a runbook or change note, and keep the public repository free of anything specific to the deployment, enforced by an automated gate.
