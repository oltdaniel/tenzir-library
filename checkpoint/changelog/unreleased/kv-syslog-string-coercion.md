---
title: Keep numeric names on the pipe-KV syslog path
type: bugfix
authors:
  - oltdaniel
  - claude
created: 2026-08-20T00:00:00Z
---

`parse_kv` infers a type per value, so a Check Point field whose text looks like
a number or an address reached the OCSF mappers as an `int64` or an `ip`.
`ocsf::cast` drops a mistyped value rather than converting it, so an all-digit
login name emptied `actor.user.name`, and an `sname` or `dname` naming a bare
address emptied `src_endpoint.hostname` and `dst_endpoint.hostname`. The `user`,
`sname`, `dname`, `object`, `app_name`, and `product` fields now coerce to
strings at map time.

Only the syslog paths were affected; the JSON export states its types. A new
test runs the pipe-KV syslog path all the way through `ocsf::cast`, which
nothing covered before.
