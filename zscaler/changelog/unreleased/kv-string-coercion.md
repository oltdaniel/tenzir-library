---
title: Keep numeric locations, departments, and hosts
type: bugfix
authors:
  - oltdaniel
  - claude
created: 2026-08-20T00:00:00Z
---

`zscaler::read_kv` infers a type per value, so a quoted ZIA field whose text
looks like a number or an address arrived as an `int64` or an `ip`.
`ocsf::cast` drops a mistyped value rather than converting it, which emptied
eight fields whenever the source used numeric codes: a numeric location code
(`proxy_endpoint.name`), a department ID (`actor.user.org.ou_name`), a login ID
(`actor.user.name`), a device named by address (`device.hostname`), a numeric
device owner (`device.owner.name`), a bare-address Host header
(`dst_endpoint.domain`), and numeric app or threat names (`app_name`,
`malware[].name`). All eight now coerce to strings at map time.
