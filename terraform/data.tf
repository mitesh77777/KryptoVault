###############################################################################
# Enclave-Guard – Data Sources
###############################################################################

# Current AWS account & caller identity
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

# Latest Amazon Linux 2023 AMI (used when var.ami_id is empty)
data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

# Default VPC (fallback when no VPC/subnet provided)
data "aws_vpc" "default" {
  count   = var.vpc_id == "" ? 1 : 0
  default = true
}

data "aws_subnets" "default" {
  count = var.subnet_id == "" ? 1 : 0

  filter {
    name   = "vpc-id"
    values = [var.vpc_id == "" ? data.aws_vpc.default[0].id : var.vpc_id]
  }

  filter {
    name   = "default-for-az"
    values = ["true"]
  }
}
