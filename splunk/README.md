# Splunk Cross-Platform Validation

To validate that the detection logic in Sentinel Lake isn't tied to one
platform, the same three detections implemented in `src/normalize.py`
(and queryable via Athena/SQL in the AWS pipeline) were reproduced in
Splunk using SPL, against the same raw sample logs.

| Detection | AWS/Python/SQL | Splunk (SPL) |
|---|---|---|
| SSH brute force (3+ failed logins, same IP) | `normalize.py:detect()` / Athena SQL | `searches.spl` #1 |
| Firewall blocks by source IP | `normalize.py:detect()` / Athena SQL | `searches.spl` #2 |
| High-confidence correlation (same IP, both signals) | `normalize.py:detect()` / Athena SQL | `searches.spl` #3 |

## Running it

```bash
cd splunk
docker compose up -d
# wait ~2-4 min for Splunk to finish starting — check with:
docker compose logs -f splunk
```

Once you see `Splunk => Started` in the logs, open **http://localhost:8000**
and log in with `admin` / the password set in `docker-compose.yml`
(defaults to `Splunk123!` — override via the `SPLUNK_PASSWORD` env var).

Upload `sample-logs/auth.log` and `sample-logs/firewall.log` (Settings →
Add Data → Upload), setting sourcetypes to `linux_secure` and
`linux_firewall` respectively and the index to `security`, then run the
searches in `searches.spl`.

**Verified results** (against the included sample logs):
- SSH brute force: `203.0.113.42` flagged with 4 failed logins
- Firewall blocks: `203.0.113.42` and `45.146.165.9`, 2 blocks each
- High-confidence correlation: `203.0.113.42` — the only IP present in
  both signals, matching the same top-priority threat the AWS/Athena
  pipeline surfaces

## Why this matters

The underlying question — "which IPs are brute-forcing SSH, and which of
those are also getting firewall-blocked?" — doesn't change based on
tooling. Reproducing it in both a serverless AWS data lake (S3 → Lambda →
Glue → Athena) and a purpose-built SIEM (Splunk) shows the same detection
logic translating cleanly across a cloud-native analytics stack and an
industry-standard SIEM platform.
