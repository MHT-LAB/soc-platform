# Sprint 0 review: foundations

**Dates:** 2026-10-17 → 2026-10-24 · **Goal:** a secure, empty skeleton with a
green pipeline, deployed to its own host, plus written decisions.
**Result:** goal met on day one; the rest of the week went to a first console
and the detection baseline.

## Shipped
| Area | What |
|---|---|
| Repository | Public-ready code repo + private deploy companion; squash-only merges; noreply commit identity |
| CI (7 gates) | Tests with strict typing, secret scan, SAST, dependency audit, Dockerfile and CI-config scan, image CVE scan + smoke test, scrub gate for private identifiers |
| Release | Digest-pinned base image, SBOM, keyless signature, signed SBOM attestation |
| Deploy | Verify signer, repository and trigger; verify the SBOM attestation; pin to digest; confirm the running digest; roll back on any failure |
| Host | Dedicated unprivileged container, no inbound ports, outbound-only tunnel; one public path (`/healthz`), everything else rejected at the edge |
| Console v0 | Tailnet-only operations page: edge tunnel, verified build, pipeline stages, live sensor fleet. Requires a verified personal identity; tagged service devices are refused |
| Detection baseline | 60 detections over 10 days sorted by cause: 0 intruder, 0 unexplained, 52% removable by rule fixes ([phase-0-baseline](../tuning/phase-0-baseline.md)) |
| Decisions | ADRs 0001-0008 |

## Caught by the gates
1. **The scrub gate caught a real leak path.** The hosting platform builds a temporary merge commit to test each pull request and authored it with the account's primary email. The gate now checks the branch's own commits, and merges set a noreply author.
2. **A signing-tool upgrade silently disabled a check.** The new bundle format no longer exposed the signed commit, so the comparison was skipped. Replaced with a stricter check (running digest = verified digest) that fails closed.
3. **An API ignored an unknown parameter.** The console's online filter used the wrong name, the API returned every sensor, and the fleet showed all-online. Caught by comparing the console with the platform's own view; fixed with a regression test against a fake API that also ignores unknown parameters.
4. **Least privilege broke a third-party action.** A secret-scanning action needed pull-request API access the read-only CI token doesn't grant. Replaced with the checksum-verified official binary.
5. **"Unknown" sensors were the network feeds.** Two unfamiliar sensors turned out to be syslog adapters re-registered under a new format; the stale original was removed.

## Decided (with reasons in ADRs)
- Postgres from day one (0001) · public code, private deploy (0002) · stack (0003) · the EDR platform stores raw telemetry (0004) · supply-chain controls (0005) · compensating controls while private (0006) · integration vendors may be named (0007) · own case store, linked platform cases (0008).
- The SOC hostname stays dark: no public status page. Live pipeline health is targeting information.

## What it taught
- **Security tooling earns its keep on day one.** Every gate added this sprint caught something real within hours.
- **Verify against a second source.** Two of five issues were found only by comparing our output with the platform's.
- **Fail closed.** A check that can silently skip is worse than no check, because it reports green.
- **The operator's own AI agent is the noisiest "attacker"** on the network, which shapes the work registry design.

## Carried into Sprint 1
- Paging (push first, email backup), ingest with signed webhooks, the case store and first migrations.
- Open `/ingest/` at the edge with signature checks and rate limits.
- Two live-rule tuning changes awaiting approval.
