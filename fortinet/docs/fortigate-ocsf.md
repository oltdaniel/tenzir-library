# FortiGate → OCSF mapping reference

This document records what the FortiGate mapping does with every field FortiOS
emits, and why. It exists so that a change in FortiGate's log format can be
diagnosed by reading rather than by re-deriving the original reasoning.

The mapping targets **OCSF 1.8.0**. `ocsf::cast` validates the result against
that schema and drops anything that is not part of it, so a field that survives
casting is a field that genuinely exists in OCSF.

## Sources

| What | Where |
| --- | --- |
| FortiOS log field meanings | [FortiGate Log Reference](https://docs.fortinet.com/document/fortigate/7.4.0/fortios-log-message-reference) |
| Log ID catalogue (the `logid` values used to disambiguate VPN events) | FortiOS Log Reference, "Log ID definitions" |
| OCSF classes, objects, and enums | [OCSF schema browser](https://schema.ocsf.io/1.8.0/) |
| Where each class goes in Sentinel | [`microsoft/docs/ocsf-sentinel.md`](../../microsoft/docs/ocsf-sentinel.md) |

## Coverage

`fortinet::fortigate::ocsf::map` dispatches on `type` and `subtype`. Every
FortiGate log reaches a class; nothing is dropped.

| FortiGate `type`/`subtype` | Operator | OCSF class | Sentinel destination |
| --- | --- | --- | --- |
| `traffic/*` | `logs/traffic` | 4001 Network Activity | ASIM NetworkSession |
| `utm/app-ctrl` | `logs/app_ctrl` | 4001 Network Activity | ASIM NetworkSession |
| `utm/ssl` | `logs/ssl` | 4001 Network Activity | ASIM NetworkSession |
| `event/wad` (SSL alerts) | `logs/wad` | 4001 Network Activity | ASIM NetworkSession |
| `utm/webfilter` | `logs/webfilter` | 4002 HTTP Activity | ASIM WebSession |
| `utm/dns` | `logs/dns` | 4003 DNS Activity | ASIM Dns |
| `utm/cifs` | `logs/cifs` | 4006 SMB Activity | ASIM NetworkSession |
| `utm/ssh` | `logs/ssh` | 4007 SSH Activity | ASIM NetworkSession |
| `utm/emailfilter` | `logs/emailfilter` | 4009 Email Activity | CommonSecurityLog |
| `event/endpoint`, `event/vpn` (tunnels) | `logs/endpoint`, `logs/vpn` | 4014 Tunnel Activity | ASIM NetworkSession |
| `utm/ips`, `utm/anomaly`, `utm/virus`, `utm/dlp`, `event/wireless` | `logs/ips`, `logs/anomaly`, `logs/virus`, `logs/dlp`, `logs/wireless` | 2004 Detection Finding | ASIM AlertEvent |
| `event/security-rating` | `logs/security_rating` | 2003 Compliance Finding | ASIM AlertEvent |
| `event/user`, `event/system` (login/logout), `event/vpn` (login failures) | `logs/authentication`, `logs/vpn` | 3002 Authentication | ASIM Authentication |
| `event/*` with `cfgpath` under `user.local` | `logs/config` | 3001 Account Change | ASIM UserManagement |
| `event/*` with `cfgpath` under `user.group` | `logs/config` | 3006 Group Management | ASIM UserManagement |
| `event/*` with any other `cfgpath` | `logs/config` | 3004 Entity Management | ASIM AuditEvent |
| `event/ha`, `event/fortiextender`, `event/connector`, `event/router`, remaining `event/*` | `base` | 0 Base Event | CommonSecurityLog |

### Why `event/*` device telemetry stays Base Event

HA cluster transitions, FortiExtender modem statistics, wireless radio
readings, and SDN connector inventory updates all report on the appliance
rather than on activity passing through it. OCSF has no class for appliance
telemetry, so these stay Base Event and reach Sentinel through
CommonSecurityLog, with every field the device reported preserved in
`AdditionalExtensions`. The reasoning per family is written out in
`operators/fortigate/ocsf/base.tql`.

## Shared behaviour

These run for most or all log families, so a field they consume will not appear
in a family's own table below.

### `ocsf/map.tql` — envelope

| FortiGate | OCSF | Notes |
| --- | --- | --- |
| `date` + `time` + `tz` | `metadata.original_time`, `time`, `timezone_offset` | FortiOS spells the offset as `+0200` or `UTC+2:00`; both are normalized to `±HHMM`. `parse_kv` reads `tz="+0200"` as the number `200`, so the sign and padding are restored before use. |
| `eventtime` | `time` | Seconds (10 digits) or nanoseconds (19 digits); values below 1e13 are treated as seconds. Preferred over `date`/`time` when present. |
| `logid` | `metadata.event_code` | Identifies the *message type* and repeats across events, so it is an event code, not a unique event ID. |
| `type` | `metadata.type` | |
| `subtype` | `metadata.log_name` | |
| `level` | `metadata.log_level` | |
| `severity`, else `level` | `severity_id` | `severity` appears only on some UTM logs; falling back to `level` keeps events from being silently downgraded to Informational. |
| `msg` | `message` | |
| `logdesc` | `status_detail` | |
| `devname` | `device.hostname` | |
| `devid` | `device.uid` | |
| `vd` | `device.zone` | The virtual domain. |

### `network_endpoints.tql` and `endpoint_context.tql`

| FortiGate | OCSF | Notes |
| --- | --- | --- |
| `srcip`/`dstip`, `srcport`/`dstport` | `src_endpoint.ip`/`port`, `dst_endpoint.ip`/`port` | |
| `srcintf`/`dstintf` | `*.interface_name` | |
| `srcintfrole`/`dstintfrole` | `*.zone` | `wan`, `lan`, `dmz`. Also drives session direction. |
| `service` | `dst_endpoint.svc_name` | The application-layer protocol for the destination port. |
| `srccountry`/`dstcountry` | `*.location.country` | FortiOS emits English country **names**, not ISO 3166-1 alpha-2 codes. The name is kept verbatim because ASIM's `SrcGeoCountry`/`DstGeoCountry` expect names, so converting to a code would force a reverse lookup one hop later. `"Reserved"` is FortiOS's placeholder for RFC 1918, loopback, and multicast addresses; it is not a country and is dropped. |
| `srcuuid`/`dstuuid` | `*.uid` | UUIDs of the matched firewall **address objects**, not of the hosts. |
| `mastersrcmac`, else `srcmac` | `src_endpoint.mac` | `mastersrcmac` is the originating device behind a NAT; `srcmac` is the immediate previous hop. The originator wins. |
| `devtype` | `src_endpoint.type` | FortiOS device fingerprint, e.g. `"Windows PC"`. |

### `connection_info.tql`

| FortiGate | OCSF | Notes |
| --- | --- | --- |
| `proto` | `connection_info.protocol_num` | |
| `sessionid` | `connection_info.uid` | |
| `srcintfrole`/`dstintfrole` (via zones) | `connection_info.direction_id` | Inbound when wan→internal, outbound when internal→wan, lateral when internal→internal. A wan-to-wan session is none of these and stays Unknown. |

### `security_control.tql` and `risk.tql`

| FortiGate | OCSF | Notes |
| --- | --- | --- |
| `profile` | `policy.name` | The UTM security profile that inspected the traffic. |
| `policyid` | `firewall_rule.uid` | The firewall policy that matched the session. Distinct from `profile`. |
| `crscore` | `risk_score` | Composite UTM risk score. |
| `crlevel` | `risk_level_id` | `low`/`medium`/`high`/`critical` → 1/2/3/4. |
| `apprisk` | `risk_details` | The application-control rating of the detected **application**, not of the event. It must not overwrite `risk_level_id`, and FortiOS grades it on five steps (low < elevated < medium < high < critical) that do not line up with OCSF's four risk levels, so it is recorded as free text with its subject named. |

### `network_evidence.tql`

Detection Finding cannot carry endpoints, files, or URLs at the top level, so
this packs them into `evidences[0]` for the `ips`, `virus`, and `dlp` families.

| FortiGate | OCSF | Notes |
| --- | --- | --- |
| `hostname` | `evidences[].dst_endpoint.hostname` | Coerced to string; `parse_kv` may read an IP-shaped hostname as an address. |
| `filename`, `filesize` | `evidences[].file.name`, `.size` | |
| `analyticscksum` | `evidences[].file.hashes[]` | A 64-character digest is recorded as SHA-256; anything else without claiming an algorithm. |
| `url` | `evidences[].url.path` (+ `hostname`) | |
| `agent` | `evidences[].http_request.user_agent` | |

## Per-family notes

Only the fields not already covered above are listed.

### `traffic` → 4001 Network Activity

| FortiGate | OCSF | Notes |
| --- | --- | --- |
| `action` | `activity_id`, `action_id`, `disposition_id` | Traffic logs are session-end summaries, so `action` says how the session *ended*: `close`→Close, `accept`→Traffic, `client-rst`/`server-rst`→Reset, `deny`→Refuse, `drop`→Fail. |
| `utmaction` | `action_id`, `disposition_id` | Takes precedence over `action` when present: it is the UTM verdict rather than the transport outcome. |
| `duration` | `duration`, `start_time` | `time` is the session *end*, so the start is derived by subtraction. |
| `sentbyte`/`rcvdbyte`, `sentpkt`/`rcvdpkt` | `cumulative_traffic.*` | Session lifetime totals, not an observation interval. |
| `sentdelta`/`rcvddelta` | `traffic.bytes_out`/`bytes_in` | Bytes since the previous log for the same session; these *are* one interval, so they sit beside the lifetime totals rather than replacing them. |
| `trandisp`, `transip`, `transport` | `src_endpoint.proxy_endpoint` or `dst_endpoint.proxy_endpoint` | SNAT rewrites the source, DNAT the destination. `transip=0.0.0.0` means no effective translation. |
| `poluuid`, `policyid`, `policytype` | `firewall_rule.uid`, `.name`, `.type` | |
| `applist` | `policy.name` | The application-control profile; `firewall_rule` already holds the firewall policy. |
| `app` | `app_name` | |
| `osname` | `src_endpoint.os.name` | |
| `service` | `app_protocol_name` | Traffic logs use this rather than `svc_name`, since the class models the protocol of the session itself. |
| `utmref` | `metadata.correlation_uid` | Links the session summary to the UTM records raised for the same session. |
| — | `observation_point_id` = 3 | A firewall observes the connection rather than being an endpoint of it. |

### `webfilter` → 4002 HTTP Activity

| FortiGate | OCSF | Notes |
| --- | --- | --- |
| `hostname` | `dst_endpoint.hostname`, `http_request.url.hostname` | |
| `url` | `http_request.url.path` | |
| `sentbyte`/`rcvdbyte` | `traffic.bytes_out`/`bytes_in` | |
| `action` | `disposition_id` | `allowed`/`blocked`/`monitored`. |
| — | `activity_id` = 0 | FortiGate does not log the HTTP verb on these records. |

### `app_ctrl` → 4001 Network Activity

| FortiGate | OCSF | Notes |
| --- | --- | --- |
| `action` | `activity_id`, `disposition_id` | `pass`/`block`/`drop`/`reset`. |
| `app` | `app_name` | |
| `applist` | `policy.name` | The app-control profile, used instead of `profile`. |
| `url` | `url.path` (+ `url.hostname`) | Network Activity has its own `url` object, so the request is recorded without reclassifying the event as HTTP — app control also matches non-HTTP applications. |
| `scertcname`, `scertissuer` | `tls.certificate.subject`, `.issuer` | Server certificate when the application ran over TLS. |
| `incidentserialno` | `metadata.correlation_uid` | Shared across every record raised for the same detection. |

### `ssl` → 4001 Network Activity

| FortiGate | OCSF | Notes |
| --- | --- | --- |
| `eventtype` | `activity_id` | `ssl-anomalies`→Reset, `ssl-exempt`→Traffic. |
| `reason` | `status_detail` | |
| `certhash` | `tls.certificate.fingerprints[]` | 40 characters is SHA-1, 64 is SHA-256, otherwise no algorithm is claimed. |
| `action` | `disposition_id` | `blocked`/`exempt`. |

### `dns` → 4003 DNS Activity

| FortiGate | OCSF | Notes |
| --- | --- | --- |
| `eventtype` | `activity_id` | `dns-query`→Query, `dns-response`→Response. |
| `qname`, `qtype`, `qclass`, `xid` | `query.hostname`, `.type`, `.class`, `.packet_uid` | |
| `ipaddr` | `answers[].rdata` | Responses only. |
| `action` | `disposition_id` | `pass`/`block`/`drop`/`monitor`. Queries carry no action. |

### `cifs` → 4006 SMB Activity

| FortiGate | OCSF | Notes |
| --- | --- | --- |
| `filename`, `filesize` | `file.name`, `.size` | |
| `filtername` | `firewall_rule.name` | The file-filter entry that matched, beneath the profile in `policy.name`. |

### `ssh` → 4007 SSH Activity

| FortiGate | OCSF | Notes |
| --- | --- | --- |
| `action` | `activity_id`, `disposition_id` | `connect`/`close`/`blocked`. |
| `login` | `dst_endpoint.owner.name` | The remote username the session authenticates as. It belongs to the endpoint's owner rather than its `uid`, which identifies the host; ASIM reads the owner as `DstUsername`. |

### `emailfilter` → 4009 Email Activity

| FortiGate | OCSF | Notes |
| --- | --- | --- |
| `from`, `to`, `subject`, `size` | `email.from`, `.to`, `.subject`, `.size` | |
| `direction` | `direction_id` | Email Activity carries direction at the top level, not in `connection_info`. |
| `service` | `protocol_name` | IMAPS, SMTPS, POP3S. Moved before `network_endpoints` runs so it is not also written to `dst_endpoint.svc_name`. |
| `action` | `disposition_id` | |

### `virus`, `ips`, `anomaly`, `dlp` → 2004 Detection Finding

| FortiGate | OCSF | Notes |
| --- | --- | --- |
| `virus`, `virusid` | `malware[].name`, `.uid` | |
| `dtype` | `malware[].classification_ids` | Translated onto the OCSF malware enum; anything outside the known set becomes Unknown rather than being forced to Virus. |
| `quarskip` | `remediation.desc` | Whether the file was quarantined and, if not, why — the outcome of the response taken. |
| `attack`, `attackid` | `finding_info.title`, `.analytic.uid` | IPS and anomaly signatures. |
| `incidentserialno` | `finding_info.uid` | The detection instance (IPS). |
| `ref` | `finding_info.src_url` | FortiGuard encyclopaedia link. |
| `count` | `count` | How many times the anomaly fired in the reporting interval. |
| `dlpextra`, `filteridx`, `filtertype` | `finding_info.title`, `.uid`, `.analytic.category` | |
| `policytype` | `firewall_rule.type` | e.g. `DoS-policy`. |

### `vpn` → 4014 Tunnel Activity or 3002 Authentication

The `subtype=vpn` family covers two differently shaped log families, told apart
by the last five digits of `logid` (the message ID from Fortinet's catalogue):
IKE negotiation logs name both ends with `locip`/`remip`, while tunnel-level
logs name only the remote peer.

Rejected logins become Authentication instead of Tunnel Activity, so that they
reach `ASimAuthenticationEventLogs` where Sentinel's built-in content looks for
them. The two VPN technologies signal a rejection differently: SSL-VPN has a
dedicated message ID, while IPsec reports it on the generic phase-1 message and
names the mechanism in `result`. Fortinet's own guidance for alerting on failed
IPsec logins is to filter that field.

Neither technology has a matching success message — a successful login of
either kind is reported as a tunnel-up event.

| FortiGate | OCSF | Notes |
| --- | --- | --- |
| `logid` 39426 | class 3002, `status_id` = Failure | SSL-VPN login failure. |
| `result` ending in "authentication failed" | class 3002, `status_id` = Failure | IPsec extended-authentication failure, reported on `logid` 37121. |
| `result` starting with `XAUTH` or `EAP` | `auth_protocol_id` | XAuth has no OCSF enum value, so it becomes Other with `auth_protocol` spelled out. |
| `vpntunnel` (on a rejected login) | `service.name` | The tunnel the client authenticated against. Reaches ASIM as `TargetAppName`. |
| `xauthuser`, `eapuser`, else `user` | `user.name` | When extended authentication is in play, `user` holds the numeric IKE identity rather than a login name, so the XAuth and EAP fields win. |
| `locip`/`locport`, `remip`/`remport` | `src_endpoint`/`dst_endpoint` | On a tunnel, oriented by `init`/`role`: the side that opened the exchange becomes the source. On a rejected login the remote peer is always the source, since it is the client that was turned away. |
| `vpntunnel`, else `phase2_name` | `tunnel_interface.name` | |
| `tunnelip` | `tunnel_interface.ip` | The address on the tunnel interface itself, not on either peer. |
| `tunnelid` | `session.uid` | |
| `tunneltype` | `protocol_name` | Defaults to IPSec. |
| `dst_host` | `dst_endpoint.hostname` | The internal host reached through the tunnel; SSL-VPN web mode reports this instead of an address. |
| `dir` | `connection_info.direction_id` | |
| `duration`, `sentbyte`/`rcvdbyte` | `cumulative_traffic.*` | Tunnel statistics describe a tunnel that is still up, so the counters are cumulative. |
| `status` | `status_id` | FortiGate spells the failure case "failure" here and "failed" on the `event/user` logs. |
| `reason`, else `result` | `status_code` | `reason` explains the outcome on SSL-VPN logs; `result` does the same on IKE logs. `OK` only restates a successful `status`, so it is dropped. |

### `config` → 3001 / 3004 / 3006

FortiGate has no dedicated user-management log type: creating a local user *is*
a configuration change to the `user.local` table. `cfgpath` therefore decides
the class.

| FortiGate | OCSF | Notes |
| --- | --- | --- |
| `user` | `actor.user.name` | The administrator who made the change. |
| `ui` | `src_endpoint.ip` and `actor.session.terminal` | `ui` is e.g. `"GUI(172.25.188.116)"` or `"jsconsole"`. The address is extracted only when something address-shaped is present, since the parentheses can hold `"local"`; the channel name becomes the session terminal. |
| `cfgtid` | `metadata.correlation_uid` | The configuration transaction ID. FortiGate emits one log per changed attribute and repeats this across all of them, so it stitches a single administrative edit back together. |
| `cfgpath`, `cfgobj` | `entity.name` | Qualified as `path/object`, the way FortiGate's own `msg` reads. |
| `cfgattr` | `entity.data` (3004) or `status_detail` (3001/3006) | e.g. `status[disable->enable]`. Account Change and Group Management have no attribute-level diff slot. |
| `action` | `activity_id` | `Add`/`Edit`/`Delete`, mapped per class. Account Change has no Update activity, so edits fall through to Other. |

### `security-rating` → 2003 Compliance Finding

| FortiGate | OCSF | Notes |
| --- | --- | --- |
| `auditid` | `finding_info.uid` | |
| `audittime` | `finding_info.created_time` | Epoch seconds. |
| `auditscore` | `compliance.desc` | Deliberately **not** `risk_score`: FortiGate's rating counts *up* for a better posture while OCSF's risk score counts up for worse, so recording it there would invert the event's meaning. |
| `criticalcount` … `lowcount` | `compliance.status_id`, `severity_id` | Fail when anything critical or high failed, Warning when only medium or low did, Pass when nothing failed. The event severity follows the worst failing bucket. |
| all counts | `count` | The number of checks the audit evaluated: everything failed plus everything passed. |

## Deliberate non-mappings

These stay in `unmapped`. They are reachable in Sentinel through
CommonSecurityLog's `AdditionalExtensions`, or through `unmapped` on the OCSF
event itself.

| Field(s) | Why not mapped |
| --- | --- |
| `cat`, `catdesc` (webfilter, dns) | Both `url.category_ids` and `url.categories` are backed by one OCSF enum drawn from a **different** taxonomy (the Symantec/Bluecoat one). FortiGuard 26 is "Malicious Websites" while OCSF 26 is "Child Pornography", and the name fails enum validation outright. Translating the ~90 FortiGuard categories needs a lookup that does not exist yet. See *Known gaps*. |
| `method` (webfilter) | Not an HTTP verb despite the name — FortiOS reports *how the filter matched* (`domain`, `url`, `pattern`). |
| `reqtype` (webfilter) | `direct` or `referral`. OCSF models the referrer as a URL, not as a navigation kind, and FortiOS does not log the referring URL. |
| `direction` (UTM families) | Reports the **attack** direction of the inspected payload (server-to-client vs. client-to-server), not the direction the session was opened in. Two records of the same session can carry opposite values. |
| `craction` | A FortiOS-internal bitmask of which UTM engines fired. |
| `appcat`, `appid` | OCSF models the application only as `app_name`; the vendor's category taxonomy and numeric signature ID have no normalized counterpart. |
| `appact` | The app-control action, already expressed through `disposition_id` from `utmaction`. |
| `count*` (`countapp`, `countav`, …) | Per-UTM-type counts of records merged into one traffic log. OCSF's `count` means the number of occurrences of *this* event. |
| `lanin`, `lanout`, `wanin`, `wanout` | WAN-optimization byte counters. OCSF 4001 has no `proxy_traffic`. |
| `filetype` (cifs, dlp) | FortiOS reports a file *format* (`msoffice`, `pdf`); OCSF's `file.type_id` enumerates file *kinds* (regular file, folder, symlink). `mime_type` would need a real MIME type FortiOS does not provide. |
| `icmptype`, `icmpcode`, `icmpid` | OCSF models transport detail only as far as `connection_info.protocol_num`; there is no ICMP object on any class. |
| `qtypeval` (dns) | The numeric query type; `query.type` already carries the string form and OCSF has no numeric slot. |
| `proto`, `sessionid` (emailfilter) | Email Activity carries neither `connection_info` nor `traffic` in OCSF 1.8. |
| `attachment` (emailfilter) | A yes/no flag, not a filename. OCSF models attachments as `email.files`, a list of actual files. |
| `recipient` (emailfilter) | Usually the local part only (`testpc3`) while `to` carries the full address. Mapped only when it actually contains `@`. |
| `analyticssubmit` (virus) | Whether the sample was uploaded to FortiSandbox — the vendor's downstream workflow, not the detection. |
| `epoch`, `eventid`, `filtercat` (dlp) | FortiOS-internal DLP bookkeeping with no OCSF counterpart. |
| `channeltype` (ssh) | OCSF 4007 has no SSH channel field. |
| `cookies`, `mode`, `stage`, `nextstat` (vpn) | IKE and SSL-VPN protocol internals: SPI cookies, phase-1 exchange mode, negotiation step, and FortiOS's own reporting cadence. |
| `sn` | Overloaded. On HA logs it is a hardware serial (`FG2K5E3916900348`); on `subtype=system` logs it is a log sequence number (`1557771654`). Nothing in the record says which, so binding it to `device.hw_info.serial_number` would misattribute it. |
| `srcserver`, `devcategory` | `srcserver` is a 0/1 flag qualifying the endpoint rather than describing it. `devcategory` mixes OS families ("Windows") with hardware roles ("Router"), so neither `os.type` nor `hw_info.vendor_name` fits the whole vocabulary; `devtype` already carries the finer value. |
| `event/*` telemetry (`ha_*`, `vcluster*`, radio and modem readings, connector inventory, FortiClient licence counts) | Appliance telemetry with no OCSF class. See `operators/fortigate/ocsf/base.tql`. |

## Performance

FortiGate emits many differently shaped records, and `parse_kv` gives each
distinct field set its own schema. Tenzir starts a new batch whenever the
schema changes, so an interleaved FortiGate stream degenerates into
single-event batches and the whole mapping runs once per event instead of once
per batch.

The effect is a cliff rather than a gradient, and it does not amortize: the
overhead is per event for the life of the pipeline, not a one-off cost when a
schema is first seen.

| Input (14k events, mapped to Sentinel) | Wall | CPU |
| --- | --- | --- |
| one shape | 1.6 s | 1.7 s |
| two shapes interleaved | 12.4 s | 130 s |
| six shapes interleaved | 16.2 s | 195 s |
| realistic mix (~90% traffic) | 31.7 s | 587 s |
| realistic mix, wrapped in `unordered` | **3.2 s** | **5.3 s** |

The fix is to tell the engine that only intra-schema order matters, which lets
it demultiplex the stream back into homogeneous batches. Wrapping the parse is
enough; the mapping downstream does not need to be inside the block:

```tql
unordered {
  fortinet = line.parse_kv()
}
fortinet::fortigate::ocsf::map event=fortinet
```

This is safe for every mapping in this package because they are stateless per
event: nothing depends on the order between two events, only on the contents of
each. Verified on the full test corpus, `unordered` produces byte-identical
output. The package's examples all use it.

`sort` triggers the same optimization implicitly, but it buffers the entire
stream, so it is not usable on a live feed. Neither `batch` nor the
`tenzir.demand` and `tenzir.import.batch-size` settings make any difference
here; `unordered` is the only lever that works.

## Known gaps

- **FortiGuard URL categories are not translated.** Mapping `cat`/`catdesc`
  onto OCSF's `url.category_ids` requires a FortiGuard → OCSF lookup table
  covering roughly 90 categories. Until it exists, the values are preserved
  verbatim in `unmapped` and do not reach ASIM's `UrlCategory`.
- **Long numeric identifiers lose precision at parse time.** `parse_kv` reads a
  value above `uint64` max as a double, so the 20-digit `iccid` arrives as
  `8.930272040303814e+19`. The boundary is that maximum, not a digit count:
  19-digit values stay exact. This happens before the mapping runs, so no
  change to the mappers can recover it — the value has to be kept as text at
  parse time, for which `split_regex` on the raw line works where `parse_kv`
  and `parse_grok` both coerce.

## Checking coverage after a FortiOS change

The mapping's own test corpus lives in `tests/fortigate/inputs/`. To see what a
new or changed log leaves behind, add it there and list what stayed in
`unmapped`, grouped by log family:

```tql
from_file f"{env("TENZIR_INPUTS")}/*.txt" {
  read_lines
}
fortinet = line.parse_kv()
fortinet::fortigate::ocsf::map event=fortinet
this = fortinet
family = f"{metadata.type}/{metadata.log_name}"
f = unmapped.drop_null_fields().keys()
unroll f
summarize family, fields=distinct(f)
sort family
```

Run it with `TENZIR_INPUTS=fortinet/tests/fortigate/inputs uvx tenzir
--package-dirs=. -f <file>.tql`. Anything listed is either a genuine gap or
belongs in the *Deliberate non-mappings* table above.

To confirm nothing is being invented, run the same corpus through
`ocsf::derive | ocsf::cast` and watch for warnings: `ocsf::cast` drops any field
that OCSF 1.8 does not define, and says which.
