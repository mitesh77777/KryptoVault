###############################################################################
# Enclave-Guard – IAM Role & Instance Profile for the Parent EC2 Instance
#
# The parent instance needs:
#   - kms:Sign (but only the *enclave* can actually use it via attestation)
#   - kms:GetPublicKey (to derive the Hedera account)
#   - kms:DescribeKey (for key metadata)
#   - SSM access for secure session management (no SSH keys needed)
###############################################################################

# ── Assume-Role Trust Policy ────────────────────────────────────────────────

data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    sid     = "EC2AssumeRole"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

# ── IAM Role ────────────────────────────────────────────────────────────────

resource "aws_iam_role" "enclave_parent_role" {
  name               = "${var.project_name}-parent-instance-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json
  description        = "Role for the Enclave-Guard parent EC2 instance"

  tags = {
    Name = "${var.project_name}-parent-role"
  }
}

# ── KMS Signing Policy ─────────────────────────────────────────────────────

data "aws_iam_policy_document" "kms_signing" {
  statement {
    sid    = "AllowKMSSigning"
    effect = "Allow"
    actions = [
      "kms:Sign",
      "kms:GetPublicKey",
      "kms:DescribeKey"
    ]
    resources = [
      aws_kms_key.enclave_signing_key.arn
    ]
  }
}

resource "aws_iam_role_policy" "kms_signing_policy" {
  name   = "${var.project_name}-kms-signing"
  role   = aws_iam_role.enclave_parent_role.id
  policy = data.aws_iam_policy_document.kms_signing.json
}

# ── SSM Session Manager Access (secure alternative to SSH) ──────────────────

resource "aws_iam_role_policy_attachment" "ssm_access" {
  role       = aws_iam_role.enclave_parent_role.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# ── CloudWatch Logging for Audit Trail ──────────────────────────────────────

data "aws_iam_policy_document" "cloudwatch_logs" {
  statement {
    sid    = "AllowCloudWatchLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams"
    ]
    resources = [
      "arn:${data.aws_partition.current.partition}:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/enclave-guard/*"
    ]
  }
}

resource "aws_iam_role_policy" "cloudwatch_policy" {
  name   = "${var.project_name}-cloudwatch-logs"
  role   = aws_iam_role.enclave_parent_role.id
  policy = data.aws_iam_policy_document.cloudwatch_logs.json
}

# ── Instance Profile ────────────────────────────────────────────────────────

resource "aws_iam_instance_profile" "enclave_parent_profile" {
  name = "${var.project_name}-parent-instance-profile"
  role = aws_iam_role.enclave_parent_role.name

  tags = {
    Name = "${var.project_name}-parent-profile"
  }
}
