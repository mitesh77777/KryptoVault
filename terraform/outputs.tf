# ──────────────────────────────────────────────────────────────
# Enclave-Guard – Outputs
# ──────────────────────────────────────────────────────────────

output "instance_public_ip" {
  description = "Elastic IP of the parent EC2 instance"
  value       = aws_eip.parent.public_ip
}

output "instance_id" {
  description = "EC2 Instance ID"
  value       = aws_instance.enclave_parent.id
}

output "kms_key_id" {
  description = "KMS Key ID for Hedera signing"
  value       = aws_kms_key.hedera_signing_key.key_id
}

output "kms_key_arn" {
  description = "KMS Key ARN"
  value       = aws_kms_key.hedera_signing_key.arn
}

output "kms_alias" {
  description = "KMS Key Alias"
  value       = aws_kms_alias.hedera_signing_key_alias.name
}

output "iam_role_arn" {
  description = "IAM Role ARN for the EC2 instance"
  value       = aws_iam_role.enclave_parent_role.arn
}

output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}

output "security_group_id" {
  description = "Security Group ID"
  value       = aws_security_group.enclave_sg.id
}

output "cloudtrail_arn" {
  description = "CloudTrail ARN for KMS audit"
  value       = aws_cloudtrail.kms_audit.arn
}
