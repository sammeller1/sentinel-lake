# How I Built Sentinel Lake
### A serverless security log pipeline on AWS — S3 → Lambda → Athena, all in Terraform

This is the full walkthrough of how I built [Sentinel Lake](https://github.com/sammeller1/sentinel-lake): a pipeline that ingests messy security logs, normalizes them into one common schema, and lets you run SQL — including cross-source threat correlation — over the result. Everything is provisioned as code and runs serverless.

---

## The problem it solves

Security logs are a mess. The same attacker shows up in your SSH logs, your sudo logs, and your firewall logs — but each one is a different format, with the data in a different place:
An analyst can't query across those — the IP lives in a different spot in each line. **The fix is normalization:** map every source into one shared schema, so all of them become a single queryable dataset. That's exactly what commercial tools (and Amazon Security Lake) do, using an open standard called **OCSF** (Open Cybersecurity Schema Framework).

---

## The architecture
Four moving parts: two S3 buckets (a raw landing zone and a processed zone), a Lambda that does the normalization, an S3 event that triggers it automatically, and Athena to query the output.

---

## Prerequisites

- An AWS account (the free tier covers this easily — set a **zero-spend budget alert** first)
- AWS CLI, Terraform, and Python 3 installed
- `aws configure` done, with `aws sts get-caller-identity` returning your account

---

## Phase 1 — The normalizer (the core idea)

Before any cloud, the heart of the project is a Python function that turns one raw line into a normalized event. Each log source gets a regex; the output is always the same OCSF-style shape.

```python
def normalize(line):
    m = SSH_RE.search(line)
    if m:
        failed = m.group("result") == "Failed"
        return {
            "class_name": "Authentication", "class_uid": 3002,
            "activity": "Logon",
            "status": "Failure" if failed else "Success",
            "src_endpoint": {"ip": m.group("src_ip"), "port": int(m.group("port"))},
            "actor": {"user": {"name": m.group("user")}},
            "metadata": {"product": "sshd", "log_source": "linux_auth"},
            "raw_event": line,
        }
    # ... firewall (Network Activity / 4001), sudo, etc.
```

**Why this matters:** an SSH event and a firewall event are different `class_name`s, but both expose `src_endpoint.ip` in the *same place*. That shared field is what makes cross-source correlation possible later. The whole project rests on this one design decision.

---

## Phase 2 — Wrap it in AWS

Everything below is Terraform. The workflow for every file is the same three commands:

```bash
terraform init    # download providers (once)
terraform plan    # dry run — see what WILL change, touch nothing
terraform apply   # make it real (type 'yes')
```

`plan` before `apply` is the habit that keeps you safe — always read what it's about to do.

### 2a — The S3 buckets (`main.tf`)

```hcl
resource "random_id" "suffix" { byte_length = 4 }   # bucket names are globally unique

resource "aws_s3_bucket" "raw" {
  bucket = "sentinel-lake-raw-${random_id.suffix.hex}"
}
resource "aws_s3_bucket" "processed" {
  bucket = "sentinel-lake-processed-${random_id.suffix.hex}"
}

# block all public access on both — security default
resource "aws_s3_bucket_public_access_block" "raw" {
  bucket                  = aws_s3_bucket.raw.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

### 2b — The Lambda + a least-privilege IAM role (`lambda.tf`)

The Lambda runs your normalizer. The important part is the **IAM policy** — it grants exactly three things and nothing else:

```hcl
resource "aws_iam_role_policy" "lambda_policy" {
  role = aws_iam_role.lambda_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "ReadRawOnly",       Effect = "Allow", Action = ["s3:GetObject"],
        Resource = "${aws_s3_bucket.raw.arn}/*" },
      { Sid = "WriteProcessedOnly", Effect = "Allow", Action = ["s3:PutObject"],
        Resource = "${aws_s3_bucket.processed.arn}/*" },
      { Sid = "WriteLogs",         Effect = "Allow",
        Action = ["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],
        Resource = "arn:aws:logs:*:*:*" }
    ]
  })
}
```

**Least privilege** is the whole point here: this function can read one bucket, write one bucket, and log. If it were ever compromised, the blast radius is two buckets — it can't touch anything else in the account. Wide-open IAM permissions are the #1 cloud security mistake; scoping to the minimum is what signals you actually understand security. It's the same deny-by-default idea Zero Trust is built on.

The Lambda handler itself just reads the uploaded object, runs each line through `normalize()`, and writes JSON Lines to the processed bucket.

### 2c — Fire it automatically on upload (`trigger.tf`)

This is what makes it a *pipeline* instead of a script you run by hand — an S3 event triggers the Lambda whenever a new log lands:

```hcl
resource "aws_s3_bucket_notification" "raw_to_lambda" {
  bucket = aws_s3_bucket.raw.id
  lambda_function {
    lambda_function_arn = aws_lambda_function.normalizer.arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "incoming/"
  }
  depends_on = [aws_lambda_permission.allow_s3]
}
```

Event-driven means it processes logs *as they arrive* — no scheduler, no server sitting idle. That's the serverless model: you pay only when data actually flows.

### 2d — Query it with Athena (`athena.tf`)

A Glue table describes the shape of the JSON in the processed bucket so Athena can run SQL against it. Once that's applied, you query normalized logs like a database:

```sql
-- Which IPs are hammering us?
SELECT src_endpoint.ip AS attacker_ip, COUNT(*) AS failed_logins
FROM sentinel_lake.events
WHERE class_name = 'Authentication' AND status = 'Failure'
GROUP BY src_endpoint.ip
ORDER BY failed_logins DESC;
```

---

## The payoff: cross-source correlation

This is the query that proves the whole thing. Because every source shares one schema, I can **JOIN a firewall log to an SSH log on the attacker's IP** — surfacing a threat that neither log shows on its own:

```sql
SELECT a.src_endpoint.ip AS threat_ip,
       COUNT(DISTINCT a.time) AS failed_logins,
       COUNT(DISTINCT f.time) AS firewall_blocks
FROM sentinel_lake.events a
JOIN sentinel_lake.events f
  ON a.src_endpoint.ip = f.src_endpoint.ip
WHERE a.class_name = 'Authentication' AND a.status = 'Failure'
  AND f.class_name = 'Network Activity' AND f.status = 'Blocked'
GROUP BY a.src_endpoint.ip;
```

Result: one IP appearing in **both** your auth failures and your firewall blocks — a high-confidence threat. A brute-force alert alone is noisy; correlating it with firewall activity across two different log formats is a real signal. **That JOIN is impossible without normalization.** That's the entire argument for the pipeline.

---

## Cost & teardown

At small data sizes this runs for effectively nothing: S3 and Lambda sit near-free at rest, and Athena charges per query (fractions of a cent on kilobytes). A zero-spend budget alert emails you if anything ever registers.

When you're done, one command removes the whole stack:

```bash
terraform destroy   # empty the buckets first if it complains they're not empty
```

…and `terraform apply` rebuilds it identically in about two minutes. That reproducibility — tear down, stand back up from code — *is* the Infrastructure-as-Code story.

---

## What each piece taught me

- **S3** — the data lake: a raw zone and a processed zone, so original logs are never mutated.
- **Lambda** — serverless compute; the normalizer runs on upload with no server to manage.
- **IAM** — least-privilege access; the role can do exactly what it needs and nothing more.
- **Terraform** — the entire stack as code, reviewable and reproducible.
- **Athena** — schema-on-read SQL over the normalized data, including cross-source joins.
- **OCSF** — the shared schema that turns incompatible formats into one queryable dataset.

Full source: **github.com/sammeller1/sentinel-lake**
