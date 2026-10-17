# Phase 6: Network and Third-Party Sources

## Network IDS/IPS via syslog
- The gateway sends IDS/IPS events as CEF over syslog to a collector that forwards them into the detection platform as a distinct sensor, tagged by source and client.
- **Why:** host-based EDR sees a scanner tool executed on a monitored host, but not a monitored host being scanned by something else. Wire-level IDS covers that blind spot. A host firewall that silently drops the probe leaves nothing for host telemetry to see.
- **Field mapping:** map CEF fields (category, device model, client MAC, signature) to clean routing fields so rules are simple. Default parsing works; mapping makes rules readable.
- **Rules:** start with honeypot-triggered and the highest-severity threat categories, report-only.
- **Correlation:** join network events to endpoints by address and client device, so a scan source and a host detection can become one case and feed the stacked-evidence gate.

## Managed MDR vendor: read-only lane
- Ingest incidents and show them in the same queue labeled as handled by the vendor.
- **No analyst triage and no automated actions** on those cases. The vendor's analysts own the response.
- **Cross-link only:** if the same host or indicator appears in another case, link the cases and add a note.
- Page level follows the vendor's severity; no double paging.

## Adapters
A small adapter per source maps events to the normalized alert. Prefer direct webhook to ingest; use a workflow tool only where a vendor needs reformatting. Per-site network adapters need a site id or tag so events attribute to the right client.

## Unmapped and noisy sources
Unmapped events go to the Unassigned queue. New sources are baselined and tuned before they can page.

## Acceptance
- A synthetic and a real honeypot trigger both become cases attributed to the right site.
- A vendor incident shows read-only with no triage and no action buttons.
- A network scan plus a host detection on the same device merge into one case.
