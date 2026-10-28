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

**Database isolation (Sprint 1).** PostgreSQL runs in its own container on an internal compose network shared only with the public app and the one-off migration job. The tunnel is not on that network, nothing is published on the host, and the `postgres` superuser is refused over the network. The public app connects as `soc_ingest`, a role with no table privileges whose only capability is calling `ingest_alert()`; the owner credentials exist only for the migration job. A compromised public app can therefore add alerts through that function and read nothing back. Residual risk: root on the host can read the database and every secret file, which is the same trust boundary as the rest of the host.

**Pager worker (Sprint 1).** A separate service turns alerts into cases and pushes them to a phone through a third-party push server. It is on the internal database network and on its own outbound-only network, and not on the tunnel's network; nothing listens and nothing is published. It logs in as `soc_worker`, a role with no table privileges whose only way in is six functions that never return the raw payload and never accept a client id from the caller; a compromised worker can read pushes' worth of fields and mark pages sent or failed, and change nothing else. What crosses the push server is generic by design: client, rule name, host name, time and a short case id, built from sanitised fields (control characters stripped, lengths capped, plain text) and sent as JSON in the request body, never as HTTP headers, so alert text cannot inject a header or a second topic. The topic is the only secret in a push (on the public server anyone who knows it can read and post to it): it is generated on the host, stored mode 600 and in the secrets manager, never logged, never in a URL, never in an error code, and the client refuses redirects and any scheme but https. Floods are bounded: at most `SOC_PAGE_CAP` pushes per window, the rest wait and one notice says so. Residual risks: the egress network is not restricted to one domain (Docker cannot allowlist names; the host firewall is the open item); the push server sees the topic and the metadata above; a person who forges alerts through a stolen ingest key can buzz the phone up to the cap.

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
