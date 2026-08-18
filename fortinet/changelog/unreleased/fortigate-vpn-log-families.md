---
title: Cover the full range of FortiGate VPN logs
type: change
authors:
  - oltdaniel
  - claude
created: 2026-08-18T00:00:00Z
---

The VPN mapping was built around a single log shape — IKE phase 1 negotiation —
and mishandled everything else that FortiGate reports under `subtype=vpn`.
It now recognizes the two families the log ID catalogue defines:

- IKE negotiation and SA lifecycle (message IDs 37120-37144) name both ends of
  the exchange. `init` and `role` decide which side opened it, so the initiator
  becomes the source endpoint instead of the FortiGate always being the source.
- Tunnel-level events — IPsec tunnel up, down, and statistics (23101-23103) and
  the SSL-VPN families (39424-39426, 39936-39953) — name only the remote peer
  and carry `tunnelid`, `tunneltype`, and lifetime counters. These previously
  produced a warning per event, because `locip`, `locport`, and `remport` were
  read as if they were always present.

SSL-VPN login failures now map to Authentication (3002) rather than Tunnel
Activity, reaching Microsoft Sentinel as `ASimAuthenticationEventLogs` with the
FortiGate `reason` as the result detail. The catalogue defines no matching
success message: a successful SSL-VPN login is reported as a tunnel-up event.

Tunnel statistics keep their counters: `duration`, `sentbyte`, and `rcvdbyte`
become `cumulative_traffic` with session start and end times, so ASIM receives
`NetworkDuration`, `SrcBytes`, and `DstBytes` instead of leaving them unmapped.
`tunnelid` becomes the session identifier and `tunneltype` the tunnel protocol,
so IPsec and the two SSL-VPN modes are distinguishable.
