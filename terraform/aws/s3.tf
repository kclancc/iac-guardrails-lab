# S3 bucket with intentional misconfigurations.

resource "aws_s3_bucket" "logs" {
  bucket = "guardrails-lab-logs-${random_id.suffix.hex}"

  tags = {
    Name    = "guardrails-lab-logs"
    purpose = "iac-scan-sandbox"
  }
}

resource "random_id" "suffix" {
  byte_length = 4
}

# Missing server-side encryption and versioning on purpose.
# Public access block is also not defined below to leave a finding surface.

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
