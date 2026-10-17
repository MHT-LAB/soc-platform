# 0005: Supply-chain controls

**Status:** accepted · **Date:** 2026-10-17

## Decision
- **Actions pinned to commit SHAs**, with the version in a comment. A moved or
  compromised tag can't change what CI runs. Dependabot proposes bumps.
- **Base image pinned by digest.**
- **Python dependencies locked with hashes** (`uv.lock`); the audit job
  installs nothing that doesn't match.
- **Every image gets an SBOM** (Syft, SPDX) and is **signed with cosign keyless
  signing** using the workflow's GitHub OIDC identity. The SBOM is attached as a
  signed attestation.
- **Deploy verifies before running**: the host's deploy script checks the
  signature against the expected workflow identity and refuses anything else.
- **No auto-updaters on the SOC host.** Images change only through a signed
  release and an explicit deploy.

## Consequences
- Keyless signing records an entry in the public Sigstore transparency log,
  which includes the repository and workflow name. Acceptable, since the repo
  is intended to be public.
- Pin bumps arrive as weekly PRs that must pass the same gates.
