# ---------------------------------------------------------
# Sentinel Lake - Phase 2b: Lambda normalizer + IAM
# ---------------------------------------------------------

# zip src/ (normalize.py + lambda_function.py) into a deployment package
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../src"
  output_path = "${path.module}/lambda.zip"
}

# IAM role the Lambda assumes when it runs
resource "aws_iam_role" "lambda_role" {
  name = "sentinel-lake-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

# LEAST-PRIVILEGE policy: read raw only, write processed only, write logs. Nothing else.
resource "aws_iam_role_policy" "lambda_policy" {
  name = "sentinel-lake-lambda-policy"
  role = aws_iam_role.lambda_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadRawBucketOnly"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${aws_s3_bucket.raw.arn}/*"
      },
      {
        Sid      = "WriteProcessedBucketOnly"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.processed.arn}/*"
      },
      {
        Sid      = "WriteLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

resource "aws_lambda_function" "normalizer" {
  function_name    = "sentinel-lake-normalizer"
  role             = aws_iam_role.lambda_role.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.12"
  timeout          = 30
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      PROCESSED_BUCKET = aws_s3_bucket.processed.id
    }
  }
}

output "lambda_name" {
  value = aws_lambda_function.normalizer.function_name
}
