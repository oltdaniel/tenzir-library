---
title: Improved FortiGate network session semantics
type: change
authors:
  - oltdaniel
  - codex
created: 2026-08-14T00:00:00Z
---

FortiGate traffic logs now model the firewall as an intermediary observation
point, expose application protocols and endpoint names, and normalize firewall
actions. Session lifetime counters use OCSF `cumulative_traffic`, while session
start, end, and duration are available at the event level.

FortiGate `logid` now maps to `metadata.event_code` because it identifies a
message type and is not unique per event.
