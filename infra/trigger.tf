# ---------------------------------------------------------
# Sentinel Lake - Phase 2c: auto-trigger Lambda on S3 upload
# ---------------------------------------------------------

# permission: allow the raw bucket to invoke the Lambda
resource "aws_lambda_permission" "allow_s3" {
  statement_id  = "AllowExecutionFromS3"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.normalizer.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.raw.arn
}

# notification: fire the Lambda when an object lands under incoming/ in raw
resource "aws_s3_bucket_notification" "raw_to_lambda" {
  bucket = aws_s3_bucket.raw.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.normalizer.arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "incoming/"
  }

  depends_on = [aws_lambda_permission.allow_s3]
}
