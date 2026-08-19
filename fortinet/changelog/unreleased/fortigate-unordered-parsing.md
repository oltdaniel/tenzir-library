---
title: Parse FortiGate logs unordered for throughput
type: change
authors:
  - oltdaniel
  - claude
created: 2026-08-19T00:00:00Z
---

The examples now wrap the key-value parse in `unordered`, which raises
throughput on mixed FortiGate logs by roughly ten times and cuts CPU by two
orders of magnitude.

FortiGate emits many differently shaped records and `parse_kv` gives each field
set its own schema. Tenzir starts a new batch whenever the schema changes, so an
interleaved stream degenerates into single-event batches and the mapping runs
once per event rather than once per batch. `unordered` tells the engine that
only intra-schema order matters, letting it demultiplex the stream back into
homogeneous batches.

This is safe because the mappings are stateless per event, and it produces
identical output. `docs/fortigate-ocsf.md` records the measurements.
