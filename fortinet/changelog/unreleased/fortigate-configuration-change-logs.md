---
title: Map FortiGate configuration changes to auditable OCSF classes
type: feature
authors:
  - oltdaniel
  - claude
created: 2026-08-18T00:00:00Z
---

FortiGate records administrative configuration changes across several event
subtypes — `system`, `router`, `sdwan`, and others — all carrying `cfgpath`,
the configuration table that was touched. Those logs now map by that path:
changes below `user.local` become OCSF Account Change (3001), changes below
`user.group` become Group Management (3006), and everything else becomes Entity
Management (3004). Previously they all fell through to Base Event.

Downstream this means FortiGate administrative activity reaches Microsoft
Sentinel as `ASimUserManagementActivityLogs` and `ASimAuditEventLogs` records,
naming the administrator, the object they changed, and the address they
connected from. The new `from-file-to-asim` example shows the full path.

The SSH inspection mapping now reports the remote `login` as the destination
endpoint's owner instead of its `uid`, so the username reaches ASIM as
`DstUsername` rather than being mistaken for a device identifier.
