# acme-demo

Synthetic demo tenant: one client, one site, two endpoints and one source, all made
up. `seed.json` is loaded by `soc_api.seed.seed_demo`; real client rows live in the
private deploy repo and never here. The activity section also seeds twelve sensors (one
offline) and three adapters (two syslog gateways, one quiet for days, and an email feed),
so the signal flow shows all three groups.
