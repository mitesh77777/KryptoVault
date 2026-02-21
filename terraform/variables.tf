###############################################################################
# Enclave-Guard – Terraform Variables
# Institutional-grade signing middleware for Hedera on AWS Nitro Enclaves
###############################################################################

variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project identifier used for naming and tagging"
  type        = string
  default     = "enclave-guard"
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
  default     = "dev"
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

# ---------- EC2 / Enclave ----------

variable "instance_type" {
  description = "EC2 instance type – must support Nitro Enclaves (m5a.xlarge minimum)"
  type        = string
  default     = "m5a.xlarge"
}

variable "ami_id" {
  description = "Amazon Linux 2023 AMI ID (leave empty to use latest)"
  type        = string
  default     = ""
}

variable "key_pair_name" {
  description = "Name of an existing EC2 key pair for SSH access"
  type        = string
  default     = ""
}

variable "allowed_ssh_cidrs" {
  description = "CIDR blocks allowed to SSH into the parent instance"
  type        = list(string)
  default     = ["0.0.0.0/0"]  # Tighten for production
}

# ---------- KMS / Attestation ----------

variable "enclave_pcr0_hash" {
  description = <<-EOT
    PCR0 measurement of the Nitro Enclave image (EIF).
    Run `nitro-cli describe-eif --eif-path enclave.eif` to obtain this value.
    Set to "PLACEHOLDER" during first deploy; update after building the EIF.
  EOT
  type        = string
  default     = "PLACEHOLDER"
}

variable "kms_key_deletion_window" {
  description = "Waiting period in days before KMS key deletion (7-30)"
  type        = number
  default     = 7
  validation {
    condition     = var.kms_key_deletion_window >= 7 && var.kms_key_deletion_window <= 30
    error_message = "KMS key deletion window must be between 7 and 30 days."
  }
}

variable "kms_key_alias" {
  description = "Alias for the signing KMS key"
  type        = string
  default     = "enclave-guard-secp256k1"
}

# ---------- VPC (optional – use defaults for hackathon) ----------

variable "vpc_id" {
  description = "Existing VPC ID. Leave empty to create a new one."
  type        = string
  default     = ""
}

variable "subnet_id" {
  description = "Existing subnet ID. Leave empty to create a new one."
  type        = string
  default     = ""
}

# ---------- Tags ----------

variable "tags" {
  description = "Additional tags for all resources"
  type        = map(string)
  default     = {}
}
