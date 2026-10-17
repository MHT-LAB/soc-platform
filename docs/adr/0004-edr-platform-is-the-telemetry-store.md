# 0004: The EDR/SIEM platform stores raw telemetry

**Status:** accepted · **Date:** 2026-10-17

## Context
The goal is one place to see the state of the whole SOC. Copying all raw
telemetry into this project would mean building a second SIEM: storage,
retention, indexing and cost would all double.

## Decision
The cloud EDR/SIEM platform remains the system of record for raw telemetry
(it includes a year of retention). Sources that can be routed into it are
routed into it, for example network IDS events through a syslog adapter.

This project stores what the platform doesn't model: normalized **alerts**,
**cases**, the **work registry**, **actions and approvals**, **notifications**,
**usage**, and periodic **posture snapshots** pulled from APIs (sensor fleet,
adapter health, rule inventory). The console reads raw events on demand
through the platform's API when a case needs them.

## Consequences
- Storage stays small, so the database fits a 2 GB VPS.
- Pivots into raw events depend on the platform's API being reachable; the
  case store still works without it.
