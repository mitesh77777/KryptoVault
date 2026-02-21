# ──────────────────────────────────────────────────────────────
# Enclave-Guard – Terraform Variables
# ──────────────────────────────────────────────────────────────

variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project slug used for naming resources"
  type        = string
  default     = "enclave-guard"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "subnet_cidr" {
  description = "CIDR block for the public subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "instance_type" {
  description = "EC2 instance type (must support Nitro Enclaves)"
  type        = string
  default     = "m5a.xlarge"
}

variable "ami_id" {
  description = "Amazon Linux 2023 AMI ID (Nitro-compatible). Leave empty to auto-discover."
  type        = string
  default     = ""
}

variable "enclave_cpu_count" {
  description = "Number of vCPUs allocated to the Nitro Enclave"
  type        = number
  default     = 2
}

variable "enclave_memory_mib" {
  description = "Memory in MiB allocated to the Nitro Enclave"
  type        = number
  default     = 512
}

variable "ssh_allowed_cidr" {
  description = "CIDR block allowed to SSH into the parent instance"
  type        = string
  default     = "0.0.0.0/0"
}

variable "key_pair_name" {
  description = "Name of the EC2 key pair for SSH access"
  type        = string
}

variable "enclave_pcr0" {
  description = "PCR0 hash of the Nitro Enclave Image. Set after first build."
  type        = string
  default     = ""
}

variable "hedera_network" {
  description = "Hedera network to use (testnet or mainnet)"
  type        = string
  default     = "testnet"
}

variable "tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default = {
    Project     = "enclave-guard"
    Hackathon   = "hedera-apex-2026"
    ManagedBy   = "terraform"
  }
}
