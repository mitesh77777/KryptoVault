# ──────────────────────────────────────────────────────────────
# Enclave-Guard – CloudTrail (Audit Layer)
# ──────────────────────────────────────────────────────────────

resource "aws_cloudwatch_log_group" "enclave_guard" {
  name              = "/enclave-guard/audit"
  retention_in_days = 90

  tags = {
    Name = "${var.project_name}-audit-logs"
  }
}

# CloudTrail for KMS sign operations (dual-layer audit)
resource "aws_s3_bucket" "trail_bucket" {
  bucket        = "${var.project_name}-cloudtrail-${data.aws_caller_identity.current.account_id}"
  force_destroy = true

  tags = {
    Name = "${var.project_name}-trail-bucket"
  }
}

resource "aws_s3_bucket_policy" "trail_bucket_policy" {
  bucket = aws_s3_bucket.trail_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.trail_bucket.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.trail_bucket.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

resource "aws_cloudtrail" "kms_audit" {
  name                          = "${var.project_name}-kms-trail"
  s3_bucket_name                = aws_s3_bucket.trail_bucket.id
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_logging                = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  tags = {
    Name = "${var.project_name}-kms-trail"
  }

  depends_on = [aws_s3_bucket_policy.trail_bucket_policy]
}
