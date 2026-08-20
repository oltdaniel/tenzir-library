---
title: Keep DNS queries for a literal address
type: bugfix
authors:
  - oltdaniel
  - claude
created: 2026-08-20T00:00:00Z
---

An Umbrella DNS query naming a literal address parses as an `ip` rather than a
string, and `ocsf::cast` drops a mistyped value rather than converting it, so
`query.hostname` came out empty for those records. It now coerces to a string.
