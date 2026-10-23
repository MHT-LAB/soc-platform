# Security Design and Threat Model

The SOC holds keys that can isolate endpoints and reads sensitive telemetry, so it is itself a high-value target.

## Threats and controls
| Threat | Control |
|---|---|
| Prompt injection through alert fields (command lines, hostnames, file names, network text) | Fields passed as quoted untrusted data; read-only tool set; containment gate computed in code; injection fixtures in the test corpus |
| Compromised or over-privileged key | Per-client read-only key for triage; separate narrowly scoped key for response (isolate, rejoin, tag); keys held in a secrets manager and delivered as mode-600 files; never in repository, image, or notes |
| Public ingest endpoint abuse | One public route only; per-source secret or HMAC; rate limit; body cap; vendor IP allowlists where published; everything else reachable only over the mesh VPN |
| Server compromise | Non-root service user, minimal capabilities, read-only root filesystem where possible, key-only access over the mesh VPN, automatic security updates, default-deny firewall, no inbound port forwards |
| Cross-client leakage | Row-level client id, per-client keys and model sessions, per-client caps, cross-client correlation off by default |
| Silent failure of the SOC | Heartbeat detection, external uptime monitor, independent email channel, degraded banner |
| Runaway cost | Per-client and global caps that fail closed |
| Bad automatic action | Allowlist, stacked-evidence gate in code, would-have-done mode first, reversible actions only, one-tap rejoin, client authorization flags |
| Tampering with history | Append-only case log; signed reports are immutable and versioned |
| Client data handling | Contract language on AI-assisted analysis and retention; hash-only lookups for client files; per-client retention |

## Exposure rule
The only internet-facing surface is the ingest route behind a tunnel or reverse proxy. The console and API are reachable only over the mesh VPN.

**Console isolation (Sprint 1 hardening).** The console is a separate app and a separate service. The public app contains no console routes. The console service runs on the host network, bound to the host's loopback, so containers (including the tunnel) cannot connect to it; `tailscale serve` is the only path in, and it supplies the verified identity header. Residual risk: host networking gives the console container the host's network view (LAN and loopback services), so it stays non-root, read-only and capability-free, and holds only the console allowlist and the read-only EDR key. Any process on the host can also reach `127.0.0.1:8081` and send its own `Tailscale-User-Login`; only root-level host processes run on CT 110 today, so keep it that way.

## Failure of the human link
Page acknowledgement is tracked; high/critical alerts re-page every ten minutes, then email; an optional second commander removes the single-person bottleneck.

## Public export checklist
Before any note, diagram, rule pack or repository from this project is shared publicly, grep the actual diff (not only new files) and remove or generalize:
- Host, device and account names; usernames; filesystem paths.
- Network addresses, subnet layouts, tunnel and VPN identifiers.
- Tenant, organization, sensor and installation identifiers; URLs containing them.
- Client names, contacts, contract terms, and anything from client folders.
- Credentials of any kind, including disposable lab ones.
- Branding embedded in rule names, author email addresses in rule metadata.
- Pricing and rate cards.
- Anything that describes how the notes were produced rather than what the design is.
Treat every public technical write-up as reconnaissance material for someone profiling the author. If anything trips the checklist, stop and ask before publishing.
