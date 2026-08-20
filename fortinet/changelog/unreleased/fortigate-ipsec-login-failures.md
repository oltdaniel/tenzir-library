---
title: Report failed IPsec VPN logins as failures
type: bugfix
authors:
  - oltdaniel
  - claude
created: 2026-08-20T00:00:00Z
---

A rejected IPsec VPN login reached Microsoft Sentinel as a *successful* network
session. Three defects stacked up:

- `status="failure"` did not match the status lookup, which only knew the
  `failed` spelling that the `event/user` logs use. The outcome fell through to
  Unknown, and the ASIM NetworkSession mapper resolves an unknown outcome on a
  tunnel-open event to `EventResult: "Success"`.
- `result` was dropped as redundant. It carries the whole failure on IKE logs,
  where it is the counterpart to the `reason` that SSL-VPN logs use.
- The identity was read as `user` before `xauthuser` and `eapuser`. When
  extended authentication is in play, `user` holds the numeric IKE identity,
  which then failed the OCSF cast to `user.name` and disappeared entirely.

IPsec also gains the login-failure branch that SSL-VPN already had. The two
technologies signal a rejection differently: SSL-VPN has a dedicated message ID
(39426), while IPsec reports it on the generic phase-1 message (37121) and
names the mechanism in `result`. Both now map to Authentication (3002) and
reach `ASimAuthenticationEventLogs` rather than `ASimNetworkSessionLogs`, with
the tunnel that was dialled as `TargetAppName` and XAuth or EAP as
`LogonProtocol`.

Phase-1 failures that are not authentication failures — a proposal mismatch,
for example — stay Tunnel Activity, but now correctly report `EventResult:
"Failure"` with the reason in `EventOriginalResultDetails`.
