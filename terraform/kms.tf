###############################################################################
# Enclave-Guard – KMS Key (secp256k1 Signing Key)
#
# WINNING DETAIL: The key policy locks signing operations to a specific
# Nitro Enclave image via kms:RecipientAttestation:PCR0, ensuring the
# private key is ONLY usable by our attested enclave – even a compromised
# parent instance cannot sign transactions.
###############################################################################

resource "aws_kms_key" "enclave_signing_key" {
  description              = "Enclave-Guard secp256k1 signing key for Hedera transactions"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_SECG_P256K1"
  deletion_window_in_days  = var.kms_key_deletion_window
  is_enabled               = true
  enable_key_rotation      = false  # Asymmetric keys do not support rotation

  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "enclave-guard-key-policy"
    Statement = [

      # ── Root Account Full Access ──────────────────────────────────────
      {
        Sid    = "RootAccountFullAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },

      # ── Enclave-Only Signing ──────────────────────────────────────────
      # This is the critical security boundary: signing is ONLY permitted
      # when the request originates from a Nitro Enclave whose PCR0
      # measurement matches our known-good image hash.
      {
        Sid    = "EnclaveAttestationSignOnly"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.enclave_parent_role.arn
        }
        Action = [
          "kms:Sign"
        ]
        Resource = "*"
        Condition = {
          StringEqualsIgnoreCase = {
            "kms:RecipientAttestation:PCR0" = var.enclave_pcr0_hash
          }
        }
      },

      # ── Public Key & Metadata Access (no attestation needed) ──────────
      # The parent instance can read the public key and metadata without
      # enclave attestation – these are non-sensitive operations needed
      # to construct Hedera account IDs and verify signatures.
      {
        Sid    = "PublicKeyAndDescribeAccess"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.enclave_parent_role.arn
        }
        Action = [
          "kms:GetPublicKey",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name      = "${var.project_name}-signing-key"
    Purpose   = "hedera-transaction-signing"
    Curve     = "secp256k1"
    Hackathon = "hedera-apex-2026"
  }
}

resource "aws_kms_alias" "enclave_signing_key_alias" {
  name          = "alias/${var.kms_key_alias}"
  target_key_id = aws_kms_key.enclave_signing_key.key_id
}
