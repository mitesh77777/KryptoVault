###############################################################################
# Enclave-Guard – Terraform Outputs
###############################################################################

# ── KMS ─────────────────────────────────────────────────────────────────────

output "kms_key_id" {
  description = "KMS signing key ID"
  value       = aws_kms_key.enclave_signing_key.key_id
}

output "kms_key_arn" {
  description = "KMS signing key ARN"
  value       = aws_kms_key.enclave_signing_key.arn
}

output "kms_key_alias" {
  description = "KMS key alias"
  value       = aws_kms_alias.enclave_signing_key_alias.name
}

# ── EC2 ─────────────────────────────────────────────────────────────────────

output "instance_id" {
  description = "Parent EC2 instance ID"
  value       = aws_instance.enclave_parent.id
}

output "instance_public_ip" {
  description = "Public IP of the parent instance"
  value       = aws_instance.enclave_parent.public_ip
}

output "instance_private_ip" {
  description = "Private IP of the parent instance"
  value       = aws_instance.enclave_parent.private_ip
}

# ── IAM ─────────────────────────────────────────────────────────────────────

output "iam_role_arn" {
  description = "ARN of the parent instance IAM role"
  value       = aws_iam_role.enclave_parent_role.arn
}

output "instance_profile_name" {
  description = "Instance profile name"
  value       = aws_iam_instance_profile.enclave_parent_profile.name
}

# ── Security ────────────────────────────────────────────────────────────────

output "security_group_id" {
  description = "Security group ID for the parent instance"
  value       = aws_security_group.enclave_parent_sg.id
}

# ── Configuration Hints ─────────────────────────────────────────────────────

output "enclave_pcr0_status" {
  description = "Whether PCR0 attestation is configured or still using PLACEHOLDER"
  value       = var.enclave_pcr0_hash == "PLACEHOLDER" ? "⚠️  PCR0 is PLACEHOLDER – update after building EIF" : "✅ PCR0 configured"
}

output "next_steps" {
  description = "Post-deployment instructions"
  value = <<-EOT
    ┌─────────────────────────────────────────────────────────────┐
    │  Enclave-Guard – Next Steps                                 │
    │                                                             │
    │  1. SSH into the instance:                                  │
    │     ssh ec2-user@${aws_instance.enclave_parent.public_ip}   │
    │                                                             │
    │  2. Build the enclave EIF:                                  │
    │     cd /home/ec2-user/enclave-guard && bash setup.sh        │
    │                                                             │
    │  3. Copy the PCR0 hash and update terraform.tfvars          │
    │                                                             │
    │  4. Re-apply Terraform to lock KMS to the enclave:          │
    │     terraform apply -var="enclave_pcr0_hash=<PCR0_HASH>"    │
    │                                                             │
    │  5. Run the Hedera integration:                             │
    │     node hedera/index.js                                    │
    └─────────────────────────────────────────────────────────────┘
  EOT
}
