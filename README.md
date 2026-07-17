# Sentinel Lake — Serverless Security Log Analytics Pipeline

A serverless AWS pipeline that ingests raw security logs from multiple sources,
normalizes them into a common **OCSF-style schema**, and runs SQL analytics and
cross-source threat correlation for SOC-style investigation.

**Full build walkthrough:** see [GUIDE.md](GUIDE.md)

## Architecture
All infrastructure is provisioned with **Terraform** using **least-privilege IAM**, and the
Lambda is triggered automatically by S3 uploads (event-driven, serverless).

## Status
- **Phase 1 (done):** multi-source log normalizer + detections
- **Phase 2 (done):** deployed on AWS — S3 data lake, event-triggered Lambda, Athena analytics, all Terraform
- **Phase 3 (done):** cross-platform validation — same detections reproduced in Splunk (SPL), see [splunk/](splunk/)

## Log sources normalized
| Source | Raw format | OCSF class |
|---|---|---|
| SSH auth | `sshd` syslog | Authentication (3002) |
| sudo | `sudo` syslog | Authentication (3002) |
| Firewall | `UFW BLOCK` kernel | Network Activity (4001) |

Because all sources share fields like `src_endpoint.ip`, the pipeline can **correlate across them** —
e.g. flag an IP appearing in both SSH brute-force attempts and firewall blocks as high-confidence.

## Run the normalizer locally
    python3 src/normalize.py sample-logs/auth.log sample-logs/firewall.log --detect

## Query it in the cloud (Athena)
    SELECT src_endpoint.ip AS attacker_ip, COUNT(*) AS failed_logins
    FROM sentinel_lake.events
    WHERE class_name = 'Authentication' AND status = 'Failure'
    GROUP BY src_endpoint.ip ORDER BY failed_logins DESC;

## Cross-platform validation (Splunk)
The same three detections — brute-force by IP, firewall blocks by IP, and
high-confidence cross-source correlation — are also implemented in Splunk
using SPL, run against the same sample logs, to confirm the detection
logic isn't tied to one platform:

    index=security sourcetype=linux_secure "Failed password"
    | rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
    | stats count as failed_logins by src_ip
    | where failed_logins >= 3

See [splunk/README.md](splunk/README.md) for the full setup (Docker
Compose), all three SPL queries, and verified results.

## Infrastructure (Terraform, in `infra/`)
- `main.tf` — S3 raw + processed buckets (public access blocked)
- `lambda.tf` — normalizer Lambda + least-privilege IAM role
- `trigger.tf` — S3 event notification that fires the Lambda on upload
- `athena.tf` — Glue database/table + Athena workgroup for SQL analytics

## Why normalization
An analyst can't query many raw formats at once. Mapping every source into one OCSF-style schema
turns heterogeneous text into a single queryable dataset — the approach Amazon Security Lake uses —
which is what makes detection and correlation simple.
