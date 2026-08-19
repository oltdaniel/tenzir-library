---
title: Broaden FortiGate OCSF field coverage
type: feature
authors:
  - oltdaniel
  - claude
created: 2026-08-19T00:00:00Z
---

FortiGate logs now carry considerably more of what the device reports into OCSF.
Source and destination endpoints gain geo location from `srccountry`/`dstcountry`,
address-object UUIDs, the originating MAC behind a NAT, and the FortiOS device
fingerprint. Traffic logs map the per-interval `sentdelta`/`rcvddelta` counters
alongside the existing lifetime totals, the application-control profile, and
`utmref` as a correlation ID. Application control adds the requested URL and the
server certificate, SSL inspection adds the certificate hash, and the UTM
detection families carry the inspected file, its sandbox checksum, the requested
URL, and the requesting user agent as evidence. Antivirus detections now
translate FortiOS's `dtype` onto the OCSF malware classification instead of
always reporting Virus, and record the quarantine outcome as a remediation.

Configuration changes gain the transaction ID as a correlation ID and the
management channel as the actor's session terminal, so the individual attribute
edits FortiGate emits for one administrative change can be reassembled.
