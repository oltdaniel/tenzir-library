---
title: Honor the FortiGate time zone and derive session direction
type: change
authors:
  - oltdaniel
  - claude
created: 2026-08-18T00:00:00Z
---

FortiGate writes `date` and `time` in the device's local time zone and reports
the matching UTC offset in `tz`. The OCSF mapping now reads that offset,
records it as `timezone_offset`, appends it to `metadata.original_time`, and
applies it when a log has no `eventtime` to fall back on. Previously such logs
were read as if the device ran on UTC.

`connection_info.direction_id` is now derived from the FortiGate interface
roles (`srcintfrole`/`dstintfrole`) on every log type instead of only on
traffic logs, and covers `dmz` alongside `lan` and `wan`. Internal-to-internal
sessions map to `Lateral`.

The FortiGate `direction` field no longer feeds `direction_id`. It reports the
attack direction of the inspected payload rather than the direction in which
the session was opened — two records of the same session can carry opposite
values — so it stays in `unmapped`.
