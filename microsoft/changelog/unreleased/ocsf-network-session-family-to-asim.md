---
title: Map the OCSF network-session family to ASIM NetworkSession
type: feature
authors:
  - oltdaniel
  - claude
created: 2026-08-18T00:00:00Z
---

`microsoft::asim::ocsf::map` now routes OCSF SMB Activity (4006), SSH Activity
(4007), and Tunnel Activity (4014) to ASIM `NetworkSession` records. All three
describe a connection between two endpoints, so they share the Network Activity
mapping, which moved into `microsoft::asim::ocsf::network_session`.

Each class keeps what is specific to it: SMB file and share details and SSH
HASSH fingerprints go to `AdditionalFields`, and a tunnel contributes its
interface to `DvcInterface`, its session identifier to `NetworkSessionId`, and
the identity that established it to `SrcUsername`. The application protocol
falls back to the class when the event does not name one, so an SSH session
reports `SSH` even without a service name.
