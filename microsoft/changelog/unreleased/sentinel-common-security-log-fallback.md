---
title: Route every OCSF class to a Sentinel table
type: feature
authors:
  - oltdaniel
  - claude
created: 2026-08-19T00:00:00Z
---

The new `microsoft::sentinel::map` maps an OCSF event to ASIM where a schema
exists and to CommonSecurityLog otherwise, so no event is left without a
destination. `microsoft::sentinel::common_security_log` performs the second
half and keeps the source's own fields in `AdditionalExtensions`.

`microsoft::asim::ocsf::map` is unchanged and still fails on a class it has no
ASIM schema for, which is what you want while developing a mapping.
`docs/ocsf-sentinel.md` documents the routing and the CommonSecurityLog field
mapping.
