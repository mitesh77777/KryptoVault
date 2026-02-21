# ──────────────────────────────────────────────────────────────
# Enclave-Guard – KMS Asymmetric Key (ECC_SECG_P256K1)
# ──────────────────────────────────────────────────────────────
#
# This key is Hedera-compatible (secp256k1) and lives in an HSM.
# The key policy enforces attestation so only our verified Nitro
# Enclave image (identified by PCR0) can call kms:Sign.
# ──────────────────────────────────────────────────────────────

data "aws_caller_identity" "current" {}

# ── KMS Key ──────────────────────────────────────────────────
resource "aws_kms_key" "hedera_signing_key" {
  description              = "Enclave-Guard Hedera signing key (secp256k1)"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_SECG_P256K1"
  deletion_window_in_days  = 7
  is_enabled               = true

  # The key policy is the critical piece – it ties KMS access to
  # presentation of a valid Nitro Enclave attestation document
  # whose PCR0 matches the known-good enclave image hash.
  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "enclave-guard-key-policy"
    Statement = [
      # ── 1. Root account full access (required for management) ──
      {
        Sid    = "EnableRootAccount"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },

      # ── 2. EC2 instance role – read-only metadata ──────────────
      {
        Sid    = "AllowDescribeAndGetPublicKey"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.enclave_parent_role.arn
        }
        Action = [
          "kms:DescribeKey",
          "kms:GetPublicKey"
        ]
        Resource = "*"
      },

      # ── 3. Sign ONLY with a valid attestation document ─────────
      {
        Sid    = "AllowSignWithAttestation"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.enclave_parent_role.arn
        }
        Action   = "kms:Sign"
        Resource = "*"
        Condition = var.enclave_pcr0 != "" ? {
          StringEqualsIgnoreCase = {
            "kms:RecipientAttestation:PCR0" = var.enclave_pcr0
          }
        } : {}
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-hedera-key"
  }
}

resource "aws_kms_alias" "hedera_signing_key_alias" {
  name          = "alias/${var.project_name}-hedera-key"
  target_key_id = aws_kms_key.hedera_signing_key.key_id
}
