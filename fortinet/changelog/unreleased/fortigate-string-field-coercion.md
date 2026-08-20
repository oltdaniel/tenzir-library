---
title: Keep numeric usernames and bare-address hosts
type: bugfix
authors:
  - oltdaniel
  - claude
created: 2026-08-20T00:00:00Z
---

Values that FortiGate quotes as text still get a type from `parse_kv`, and
`ocsf::cast` drops a field whose type does not match the OCSF schema rather
than coercing it. Eight fields disappeared whenever the source value happened
to look like a number or an address:

- An all-digit login name — an employee or RADIUS ID — emptied `user.name` on
  the `event/user`, `event/system`, and `event/endpoint` logs, along with
  `user.groups[].name` and `actor.user.name`.
- A Host header naming a bare address emptied `dst_endpoint.hostname` on the
  `webfilter` and `app-ctrl` logs, and with it `url.hostname` and
  `http_request.url.hostname`, which are derived from it.
- A resolved device name that is an address emptied `src_endpoint.name` and
  `dst_endpoint.name` on the `traffic` logs.

These now coerce to strings at map time. The loss was quiet: the pipeline
warned once per event and kept going, so the only symptom was an empty column
in Sentinel.
