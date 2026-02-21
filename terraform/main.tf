# ──────────────────────────────────────────────────────────────
# Enclave-Guard – Provider & Backend
# ──────────────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Optional: Uncomment and configure for remote state
  # backend "s3" {
  #   bucket         = "enclave-guard-tfstate"
  #   key            = "terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  #   dynamodb_table = "enclave-guard-tflock"
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = var.tags
  }
}
