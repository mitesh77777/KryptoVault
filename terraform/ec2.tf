# ──────────────────────────────────────────────────────────────
# Enclave-Guard – EC2 Instance (Nitro Enclave Parent)
# ──────────────────────────────────────────────────────────────

# Auto-discover latest Amazon Linux 2023 AMI if not supplied
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

locals {
  ami_id = var.ami_id != "" ? var.ami_id : data.aws_ami.al2023.id
}

# ── User Data – bootstrap the parent instance ───────────────
locals {
  user_data = <<-EOF
    #!/bin/bash
    set -euo pipefail

    # ── System packages ──────────────────────────────────────
    dnf update -y
    dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel docker git

    # ── Enable Nitro Enclaves allocator ──────────────────────
    cat > /etc/nitro_enclaves/allocator.yaml <<ALLOCATOR
    ---
    memory_mib: ${var.enclave_memory_mib}
    cpu_count: ${var.enclave_cpu_count}
    ALLOCATOR

    systemctl enable --now nitro-enclaves-allocator.service
    systemctl enable --now docker

    # Add ec2-user to required groups
    usermod -aG ne ec2-user
    usermod -aG docker ec2-user

    # ── Install Node.js 20 LTS ───────────────────────────────
    curl -fsSL https://rpm.nodesource.com/setup_20.x | bash -
    dnf install -y nodejs

    # ── Clone project repository ─────────────────────────────
    cd /home/ec2-user
    git clone https://github.com/mitesh101010/hederaawskms.git enclave-guard || true

    echo "=== Enclave-Guard bootstrap complete ==="
  EOF
}

# ── EC2 Instance ─────────────────────────────────────────────
resource "aws_instance" "enclave_parent" {
  ami                    = local.ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.enclave_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.enclave_parent_profile.name
  key_name               = var.key_pair_name

  # CRITICAL: Enable Nitro Enclaves on the instance
  enclave_options {
    enabled = true
  }

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
    encrypted   = true
  }

  user_data = base64encode(local.user_data)

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"   # IMDSv2 enforced
    http_put_response_hop_limit = 2
  }

  tags = {
    Name = "${var.project_name}-parent"
  }

  lifecycle {
    ignore_changes = [ami]
  }
}

# ── Elastic IP for stable access ─────────────────────────────
resource "aws_eip" "parent" {
  instance = aws_instance.enclave_parent.id
  domain   = "vpc"

  tags = {
    Name = "${var.project_name}-eip"
  }
}
