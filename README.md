# Sentinel Lake — Security Log Analytics Pipeline

A security log analytics pipeline that ingests raw logs from multiple sources,
normalizes them into a common **OCSF-style schema**, and runs detections and
cross-source correlation for SOC-style investigation.

## Status
- **Phase 1 (done):** multi-source log normalizer + detections (local)
- **Phase 2 (planned):** AWS — S3 data lake, Lambda normalizer, Athena analytics, Terraform IaC

## What it does today
`src/normalize.py` reads three different raw log formats and maps every event into one shared schema:

| Source | Raw format | OCSF class |
|---|---|---|
| SSH auth | `sshd` syslog | Authentication (3002) |
| sudo | `sudo` syslog | Authentication (3002) |
| Firewall | `UFW BLOCK` kernel | Network Activity (4001) |

Because all sources share fields like `src_endpoint.ip`, it can **correlate across them** —
e.g. flag an IP appearing in both SSH brute-force attempts and firewall blocks as high-confidence.

## Run it
    python3 src/normalize.py sample-logs/auth.log sample-logs/firewall.log --detect

## Detections
- SSH brute force (failed logins per source IP over a threshold)
- Firewall blocked sources
- Cross-source correlation (same IP in auth failures AND firewall blocks)

## Why normalization
An analyst can't query many raw formats at once. Mapping every source into one OCSF-style schema
turns heterogeneous text into a single queryable dataset — the approach Amazon Security Lake uses —
which is what makes detection and correlation simple.
