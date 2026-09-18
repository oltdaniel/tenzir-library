---
title: Expand FortiGate endpoint and protocol field coverage
type: feature
authors:
  - oltdaniel
created: 2026-09-18T00:00:00Z
---

FortiGate OCSF mappings now carry source and destination hostnames, users,
passively discovered usernames, groups, operating systems, hardware vendors,
location details, and destination MAC addresses. Authenticated identities take
precedence; passive identities and their discovery methods remain available in
`unmapped`. Hostnames and usernames survive OCSF casting and reach Sentinel ASIM.

Traffic mappings now handle independent source and destination NAT, packet and
duration deltas, named policies, and URLs. HTTP transactions map to HTTP Activity
with request and response metadata. Web filtering, DNS, TLS, SMB, email, and
security findings gain protocol details and file, HTTP, and email evidence.
The mapping reference records the reviewed Flores catalogue revision and the
vendor-specific fields that remain in `unmapped`.
