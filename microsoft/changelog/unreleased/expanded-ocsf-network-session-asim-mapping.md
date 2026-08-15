---
title: Expanded OCSF Network Activity to ASIM NetworkSession mapping
type: feature
authors:
  - oltdaniel
  - codex
created: 2026-08-14T00:00:00Z
---

The OCSF to ASIM mapper now preserves substantially more Network Activity
context, including session timing and counters, protocols and direction,
reporting-device and endpoint details, users, interfaces, NAT translations,
firewall rules, risk, and fields without a dedicated ASIM counterpart.

Firewall traffic is now emitted as `NetworkSession`, while only explicitly
aggregated flow sources are emitted as `Flow`. Endpoint and layer-2 sessions
are classified separately using OCSF observation-point and endpoint data.
