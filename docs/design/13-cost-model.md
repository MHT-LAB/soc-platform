# Cost Model

> Estimates, not measurements. Replace with real usage logs after the first production weeks.

## Volume baseline
One Linux sensor, a build-heavy week: 59 detections, 18 time clusters, 25 incidents after dedupe. About 94 deduplicated cases a month at that rate (221 without dedupe). A quiet steady state will be lower; each added source and client raises it, which is why every new source is baselined and tuned before it can page.

## Per-case token assumptions
| Case type | New input | Cached re-read | Output |
|---|---|---|---|
| Light (repeat, one pass) | 4k | 8k | 0.7k |
| Typical (alert, pivots, ATT&CK, brief) | 14k | 45k | 2.5k |
| Heavy (multi-signal, with conversation) | 30k | 120k | 7k |

## Illustrative per-case cost by model size
Using illustrative per-million-token rates (small $0.10 in / $0.50 out, mid $2 / $10, large $4 / $20, cached reads at a small fraction). Recheck provider pricing at decision time.
| Case type | Small | Mid | Large |
|---|---|---|---|
| Light | about $0.001 | about $0.017 | about $0.03 |
| Typical | about $0.003 | about $0.06 | about $0.12 |
| Heavy | about $0.008 | about $0.15 | about $0.28 |

## Monthly (first tenant)
| Approach | Cost |
|---|---|
| Mid-size model, deduplicated | about $6 |
| Mid-size model, no dedupe | about $14 |
| Large model, deduplicated | about $11 |
| Tiered (small screens everything, mid triages non-benign, large for escalation and conversation) | about $2-4 plus escalations |

## Platform cost
| Stage | Hosting | Model usage | Backups | Total |
|---|---|---|---|---|
| A, self-hosted, first tenant | near $0 incremental | $6-8 | $0-2 | about $8-10 |
| B, VPS, first paying client | about $12 | $6-8 plus per-client usage | $1-2 | about $20-30 |

## Levers, in order
1. Dedupe before any model call.
2. Tune rules so known-benign patterns never fire.
3. Small-model screening tier.
4. Prompt caching on the system prompt and runbooks.
5. Large model only for escalation and live conversation.
Set a hard monthly cap that fails closed.

## Malware analysis (deferred phase)
A deep analysis with a large model is low single-digit dollars per sample at a few samples a month, with an approval gate and per-sample cap.

## Pricing a client service
Per-client cost is a share of hosting plus that client's alert volume and any deep analyses. Service pricing comes from the firm's rate card, not from this model.
