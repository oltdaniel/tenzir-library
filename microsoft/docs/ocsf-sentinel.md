# OCSF → Microsoft Sentinel mapping reference

This document records how validated OCSF 1.8 events reach Microsoft Sentinel,
which schema each class maps to, and why the classes that do not reach ASIM go
where they go.

## Sources

| What | Where |
| --- | --- |
| ASIM schemas and field definitions | [ASIM schema reference](https://learn.microsoft.com/azure/sentinel/normalization-about-schemas) |
| CommonSecurityLog columns | [CEF via AMA connector reference](https://learn.microsoft.com/azure/sentinel/cef-name-mapping) |
| CEF extension dictionary behind those columns | ArcSight CEF implementation standard |
| OCSF classes, objects, and enums | [OCSF schema browser](https://schema.ocsf.io/1.8.0/) |

## Two entry points

| Operator | Behaviour | Use when |
| --- | --- | --- |
| `microsoft::asim::ocsf::map` | Maps the classes ASIM covers and **fails** on anything else | Building or testing a mapping, where an unrecognised class should be loud |
| `microsoft::sentinel::map` | Prefers ASIM, falls back to CommonSecurityLog | Shipping a pipeline, where every event must reach a table |

`microsoft::sentinel::map` keeps its own list of the classes ASIM handles. That
list has to stay in step with `microsoft::asim::ocsf::map`: a class named in the
router but missing from the ASIM mapper fails at runtime instead of falling
back.

## Class routing

| OCSF class | ASIM schema |
| --- | --- |
| 1001 File System Activity | FileEvent |
| 1006 Scheduled Job Activity | AuditEvent |
| 1007 Process Activity | ProcessEvent |
| 1008 Event Log Activity | AuditEvent |
| 2003 Compliance Finding | AlertEvent |
| 2004 Detection Finding | AlertEvent |
| 3001 Account Change | UserManagement |
| 3002 Authentication | Authentication |
| 3003 Authorize Session | Authentication |
| 3004 Entity Management | AuditEvent |
| 3006 Group Management | UserManagement |
| 4001 Network Activity | NetworkSession |
| 4002 HTTP Activity | WebSession |
| 4003 DNS Activity | Dns |
| 4004 DHCP Activity | DhcpEvent |
| 4006 SMB Activity | NetworkSession |
| 4007 SSH Activity | NetworkSession |
| 4014 Tunnel Activity | NetworkSession |
| 201004 Windows Service Activity | AuditEvent |
| **anything else** | **none — CommonSecurityLog** |

The ASIM classes for SMB, SSH, and Tunnel Activity all delegate to the shared
`network_session` mapper, since ASIM models them as one schema.

Which physical table an ASIM record lands in is decided by the data collection
rule the workspace deploys, not by the mapping; the schema name above is what
the record declares in `EventSchema`.

### Why CommonSecurityLog for the rest

ASIM covers the schemas Microsoft has normalized, which is a deliberately
narrower set than OCSF's class list. Two things fall outside it in practice:

- **Email Activity (4009).** ASIM has no email schema. Microsoft's email tables
  (`EmailEvents` and friends) belong to Defender for Office 365 and are
  populated by that product rather than by ingestion, so they are not a
  destination a pipeline can write to.
- **Base Event (0).** Appliance telemetry — HA transitions, radio and modem
  readings, licence counts — has no OCSF class and correspondingly no ASIM
  schema.

CommonSecurityLog is the right fallback because every Sentinel workspace already
has it, a large body of built-in analytics rules and workbooks already query it,
and its `AdditionalExtensions` column is the documented home for fields outside
the standard set. Nothing is lost: the source's own fields travel there intact.

A custom table would preserve more structure, but it needs a data collection
rule deployed before anything can be written and no built-in content queries it,
so events would arrive somewhere nothing is looking.

## CommonSecurityLog field mapping

CommonSecurityLog's columns are the CEF extension dictionary under Microsoft's
names, so each row below names the CEF key the column comes from.

| OCSF | CommonSecurityLog | CEF key | Notes |
| --- | --- | --- | --- |
| `time` | `TimeGenerated` | `rt` | |
| `metadata.product.vendor_name` | `DeviceVendor` | header | Defaults to `Unknown`. |
| `metadata.product.name` | `DeviceProduct` | header | Defaults to `Unknown`. |
| `metadata.product.version` | `DeviceVersion` | header | |
| `metadata.event_code`, else `type_uid` | `DeviceEventClassID` | header | Identifies the event type within the product. |
| `activity_name`, else `class_name` | `Activity` | header (Name) | |
| `severity_id` | `LogSeverity` | header | OCSF's six steps are spread over CEF's 0-10 range: 1→1, 2→3, 3→5, 4→7, 5→9, 6→10. |
| `severity` | `OriginalLogSeverity` | | |
| `message` | `Message` | `msg` | |
| `status_detail`, else `status_code` | `Reason` | `reason` | |
| `status` | `EventOutcome` | `outcome` | |
| `action`, else `disposition` | `DeviceAction` | `act` | |
| `count` | `EventCount` | `cnt` | |
| `start_time` / `end_time` | `StartTime` / `EndTime` | `start` / `end` | |
| `finding_info.uid`, else `metadata.uid` | `ExternalID` | `externalId` | |
| `metadata.log_name` | `DeviceFacility` | `deviceFacility` | |
| `device.hostname` / `device.uid` | `DeviceName` / `DeviceExternalID` | `dvchost` / `deviceExternalId` | |
| `src_endpoint.*` | `SourceIP`, `SourcePort`, `SourceHostName`, `SourceMACAddress` | `src`, `spt`, `shost`, `smac` | |
| `src_endpoint.proxy_endpoint.*` | `SourceTranslatedAddress`, `SourceTranslatedPort` | | |
| `src_endpoint.interface_name` | `DeviceInboundInterface` | `deviceInboundInterface` | |
| `dst_endpoint.*` | `DestinationIP`, `DestinationPort`, `DestinationHostName`, `DestinationMACAddress` | `dst`, `dpt`, `dhost`, `dmac` | |
| `dst_endpoint.interface_name` | `DeviceOutboundInterface` | `deviceOutboundInterface` | |
| `connection_info.protocol_num` | `Protocol` | `proto` | CEF wants a transport *name*, so 1/6/17/58 resolve to ICMP/TCP/UDP/IPv6-ICMP and anything else is left unset rather than emitting a bare integer. |
| `app_protocol_name`, else `protocol_name` | `ApplicationProtocol` | `app` | |
| `connection_info.direction_id` | `CommunicationDirection` | `deviceDirection` | CEF is binary: inbound→0, outbound→1. OCSF's *lateral* has no CEF equivalent and stays unset rather than being forced into one of the two. |
| `traffic.bytes_in`, else `cumulative_traffic.bytes_in` | `ReceivedBytes` | `in` | The interval counters win when both are present. |
| `traffic.bytes_out`, else `cumulative_traffic.bytes_out` | `SentBytes` | `out` | |
| `http_request.url`, else `url` | `RequestURL` | `request` | Host and path are joined when both exist. |
| `http_request.http_method` | `RequestMethod` | `requestMethod` | |
| `http_request.user_agent` | `RequestClientApplication` | `requestClientApplication` | |
| `file.*` | `FileName`, `FilePath`, `FileSize`, `FileHash` | `fname`, `filePath`, `fsize`, `fileHash` | |
| `actor.user.name`, else `user.name` | `SourceUserName` | `suser` | The actor wins where both exist, because it names who acted. |
| `actor.user.uid`, else `user.uid` | `SourceUserID` | `suid` | |
| `email.from` / `email.to[0]` | `SourceUserName` / `DestinationUserName` | `suser` / `duser` | CEF's documented email convention. |
| `email.subject` | `DeviceCustomString2` (+ Label) | `cs2` | |
| `class_name` / `class_uid` | `DeviceCustomString1` / `DeviceCustomNumber1` (+ Labels) | `cs1` / `cn1` | Carries the OCSF identity, which is otherwise lost once the event leaves the OCSF schema. |
| `unmapped` | `AdditionalExtensions` | | Serialized as `key=value` pairs. |

### Detection Finding and evidences

Detection Finding carries endpoints, files, and URLs inside `evidences[]` rather
than at the top level. The CommonSecurityLog mapper falls back to
`evidences[0]` for all of those, so a firewall detection does not arrive with
empty address columns.

## Checking that everything reaches a table

Run a source's full corpus through the router and group by destination schema:

```tql
// ... source-specific parsing and OCSF mapping ...
ocsf::derive
ocsf::cast
microsoft::sentinel::map
schema = EventSchema? else "CommonSecurityLog"
summarize schema, n=count()
sort -n
```

`microsoft::sentinel::map` cannot drop an event, so every input appears in
exactly one bucket. To find classes that are *silently* falling back rather than
being mapped, swap the router for `microsoft::asim::ocsf::map`, which asserts on
any class it does not cover and names it in the failure message.
