---
title: Expanded OCSF HTTP Activity to ASIM WebSession mapping
type: feature
authors:
  - oltdaniel
  - codex
created: 2026-08-15T11:34:50.772635Z
---

The OCSF to ASIM mapper now preserves HTTP Activity network, request, response,
header, cookie, uploaded-file, user, process, API, proxy, and cloud context in
ASIM WebSession records.

The mapper classifies proxy, web-server, and API telemetry as `HTTPsession`,
`WebServerSession`, and `ApiRequest`, respectively. OCSF fields without a
dedicated ASIM counterpart remain available in `AdditionalFields`.
