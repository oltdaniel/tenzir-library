---
title: Fix the FortiGate syslog enrichment
type: bugfix
authors:
  - oltdaniel
  - claude
created: 2026-08-19T00:00:00Z
---

The syslog enrichment recorded nothing. `examples/map-to-ocsf.tql` called it
after the OCSF record had replaced the event, so the frame fields it reads were
already gone: every event carried a `metadata.loggers` entry with a null
hostname and null timestamp, nested under a spurious `ocsf` field beside the
real one.

`fortinet::fortigate::ocsf::syslog` now takes the OCSF event as an `event`
argument, like the other mapping operators, and the example calls it while
`parse_syslog`'s fields are still at the top level.

RFC 5424 frames now populate the relay hostname, name, and receipt time. BSD
frames, which FortiGate sends by default, populate the hostname and name;
their timestamp omits the year, so `logged_time` stays null rather than
claiming a year the frame never stated. A test now covers both.
