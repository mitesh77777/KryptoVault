###############################################################################
# Enclave-Guard – Provider Configuration
###############################################################################

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Uncomment for remote state in production
  # backend "s3" {
  #   bucket  = "enclave-guard-tfstate"
  #   key     = "terraform.tfstate"
  #   region  = "us-east-1"
  #   encrypt = true
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = merge(
      {
        Project     = var.project_name
        Environment = var.environment
        ManagedBy   = "terraform"
        Hackathon   = "hedera-apex-2026"
      },
      var.tags
    )
  }
}
