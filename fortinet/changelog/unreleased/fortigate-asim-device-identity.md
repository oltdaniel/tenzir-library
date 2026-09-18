---
title: Separate FortiGate ASIM device identity fields
type: fix
authors:
  - oltdaniel
  - claude
created: 2026-09-18T00:00:00Z
---

ASIM `Dvc` now uses the OCSF device UID or address instead of repeating the
device hostname. `DvcHostname` remains the host label, and `DvcFQDN` is emitted
only when OCSF provides a domain component. FortiGate identity fixtures now use
the hostname fields and no longer contain missing-field warnings.
