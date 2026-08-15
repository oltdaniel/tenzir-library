---
title: Squid access-log parsing and OCSF mapping
type: feature
authors:
  - oltdaniel
  - codex
created: 2026-08-15T10:24:15.484132Z
---

The new `squid` package parses access logs in the built-in `squid`, `common`,
`combined`, `referrer`, and `useragent` formats and maps them to OCSF 1.9.0 HTTP
Activity events:

```tql
from_file "/var/log/squid/access.log" {
  squid::read_access format="squid"
}
squid::ocsf::map
ocsf::derive
ocsf::cast
```

Use `squid::parse_access field=message, into=squid, format="combined"` to parse
forwarded records while retaining the surrounding event.

All successfully parsed access-log formats emit the same nullable fields under
the `squid.access` schema.
