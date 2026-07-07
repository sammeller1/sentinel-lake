"""
Sentinel Lake - Lambda handler (Phase 2b)
Triggered when a raw log lands in the raw S3 bucket. Reads the object,
normalizes every line into the OCSF-style schema, and writes the result
as JSON Lines to the processed bucket.
"""
import os, json, urllib.parse
import boto3
from normalize import normalize   # reuse the exact normalizer from Phase 1

s3 = boto3.client("s3")
PROCESSED_BUCKET = os.environ.get("PROCESSED_BUCKET")

def process_log_content(content):
    """Pure function: raw text in -> normalized JSONL out."""
    out = []
    for line in content.splitlines():
        ev = normalize(line)
        if ev:
            out.append(json.dumps(ev))
    return "\n".join(out)

def lambda_handler(event, context):
    for record in event["Records"]:
        src_bucket = record["s3"]["bucket"]["name"]
        key = urllib.parse.unquote_plus(record["s3"]["object"]["key"])

        obj = s3.get_object(Bucket=src_bucket, Key=key)
        content = obj["Body"].read().decode("utf-8")

        normalized = process_log_content(content)

        filename = key.rsplit("/", 1)[-1]
        out_key = f"normalized/{filename}.jsonl"
        s3.put_object(Bucket=PROCESSED_BUCKET, Key=out_key,
                      Body=normalized.encode("utf-8"))

        count = len(normalized.splitlines())
        print(f"Normalized s3://{src_bucket}/{key} -> "
              f"s3://{PROCESSED_BUCKET}/{out_key} ({count} events)")

    return {"statusCode": 200, "events_written": True}
