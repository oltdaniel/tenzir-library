---
title: Remove duplicate FortiGate OCSF fields
type: enhancement
authors:
  - oltdaniel
  - claude
created: 2026-09-18T00:00:00Z
---

FortiGate fields that have a normalized OCSF owner are now removed from
`unmapped`, including endpoint identities, policy fields, traffic counters, and
UTM-specific fields. Application protocols are represented once in the
class-level OCSF protocol field instead of being copied to the destination
endpoint. ASIM network sessions also emit FQDN columns only when OCSF provides
a domain component.
