---
title: Map FortiGate Security Rating summaries to Compliance Finding
type: feature
authors:
  - oltdaniel
  - claude
created: 2026-08-19T00:00:00Z
---

FortiGate `subtype=security-rating` summaries now map to OCSF Compliance Finding
(2003) instead of falling through to Base Event, so they reach Microsoft
Sentinel as ASIM AlertEvent records. The audit's verdict follows the worst
severity that actually failed, and the event severity follows with it.
