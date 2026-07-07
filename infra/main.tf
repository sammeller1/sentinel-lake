# ---------------------------------------------------------
# Sentinel Lake - Phase 2 infrastructure (Terraform)
# ---------------------------------------------------------

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# random suffix so bucket names are globally unique
resource "random_id" "suffix" {
  byte_length = 4
}

# --- RAW bucket: unprocessed logs land here ---
resource "aws_s3_bucket" "raw" {
  bucket = "sentinel-lake-raw-${random_id.suffix.hex}"
}

# --- PROCESSED bucket: normalized OCSF output goes here ---
resource "aws_s3_bucket" "processed" {
  bucket = "sentinel-lake-processed-${random_id.suffix.hex}"
}

# block all public access on both (security best practice)
resource "aws_s3_bucket_public_access_block" "raw" {
  bucket                  = aws_s3_bucket.raw.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "processed" {
  bucket                  = aws_s3_bucket.processed.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# print the bucket names after apply
output "raw_bucket" {
  value = aws_s3_bucket.raw.id
}

output "processed_bucket" {
  value = aws_s3_bucket.processed.id
}
