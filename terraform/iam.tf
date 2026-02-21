# ──────────────────────────────────────────────────────────────
# Enclave-Guard – IAM Role & Instance Profile for Parent EC2
# ──────────────────────────────────────────────────────────────

# ── Instance Role ────────────────────────────────────────────
resource "aws_iam_role" "enclave_parent_role" {
  name = "${var.project_name}-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-ec2-role"
  }
}

# ── KMS permissions for the instance role ────────────────────
resource "aws_iam_role_policy" "kms_access" {
  name = "${var.project_name}-kms-policy"
  role = aws_iam_role.enclave_parent_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowKMSOperations"
        Effect = "Allow"
        Action = [
          "kms:Sign",
          "kms:DescribeKey",
          "kms:GetPublicKey"
        ]
        Resource = aws_kms_key.hedera_signing_key.arn
      }
    ]
  })
}

# ── CloudWatch Logs (audit trail) ────────────────────────────
resource "aws_iam_role_policy" "cloudwatch_logs" {
  name = "${var.project_name}-cw-logs-policy"
  role = aws_iam_role.enclave_parent_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:*"
      }
    ]
  })
}

# ── SSM access for management (optional but recommended) ─────
resource "aws_iam_role_policy_attachment" "ssm_managed" {
  role       = aws_iam_role.enclave_parent_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# ── Instance Profile ────────────────────────────────────────
resource "aws_iam_instance_profile" "enclave_parent_profile" {
  name = "${var.project_name}-ec2-profile"
  role = aws_iam_role.enclave_parent_role.name
}
