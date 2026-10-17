# Security policy

This project is a security tool, so reports are welcome and taken seriously.

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting** on this repository
(Security tab, "Report a vulnerability"). Do not open a public issue.

You can expect an acknowledgement within 5 days. Please include the affected
component, steps to reproduce, and the impact you observed.

## Scope

In scope: the API, workers, console, CI workflows, container images and
detection rules in this repository.

Out of scope: third-party platforms the project integrates with. Report those
to their vendors.

## How this project protects itself

- Third-party CI actions pinned to commit SHAs; dependencies locked with hashes
- SAST, dependency, secret, Dockerfile and container scans on every pull request
- Images signed with keyless signing and shipped with an SBOM; deploys verify the signature
- Non-root, read-only containers with all Linux capabilities dropped
- A scrub gate that blocks private identifiers from ever being committed

See `docs/design/14-security-design-and-threat-model.md` for the threat model.
