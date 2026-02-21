###############################################################################
# Enclave-Guard – EC2 Instance with Nitro Enclave Support
#
# m5a.xlarge provides 4 vCPUs / 16 GiB RAM – enough to allocate
# 2 vCPUs / 4 GiB to the enclave while keeping the parent healthy.
###############################################################################

# ── Security Group ──────────────────────────────────────────────────────────

resource "aws_security_group" "enclave_parent_sg" {
  name_prefix = "${var.project_name}-parent-"
  description = "Security group for Enclave-Guard parent instance"
  vpc_id      = var.vpc_id != "" ? var.vpc_id : data.aws_vpc.default[0].id

  # SSH access (restrict in production)
  ingress {
    description = "SSH access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_ssh_cidrs
  }

  # All outbound (KMS endpoint, Hedera network, package updates)
  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-parent-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# ── User Data (Bootstrap Script) ────────────────────────────────────────────

locals {
  user_data = <<-USERDATA
    #!/bin/bash
    set -euxo pipefail

    # ── System Updates ──
    dnf update -y

    # ── Install Nitro Enclaves CLI & Allocator ──
    dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel

    # ── Configure Enclave Allocator: 2 vCPUs + 4096 MiB ──
    cat > /etc/nitro_enclaves/allocator.yaml <<'EOF'
    ---
    memory_mib: 4096
    cpu_count: 2
    EOF

    # ── Enable and Start Services ──
    systemctl enable --now nitro-enclaves-allocator.service
    systemctl enable --now docker

    # Add ec2-user to required groups
    usermod -aG ne ec2-user
    usermod -aG docker ec2-user

    # ── Install Node.js 20 LTS ──
    dnf install -y nodejs20

    # ── Install Python 3.11 for enclave build ──
    dnf install -y python3.11 python3.11-pip

    # ── Install vsock-proxy for KMS communication ──
    # The proxy bridges the enclave's vsock to the KMS HTTPS endpoint
    dnf install -y aws-nitro-enclaves-cli

    # ── Start vsock-proxy for KMS endpoint ──
    cat > /etc/systemd/system/vsock-proxy.service <<'VSOCK'
    [Unit]
    Description=Vsock Proxy for KMS
    After=network.target

    [Service]
    Type=simple
    ExecStart=/usr/bin/vsock-proxy 8000 kms.${AWS_REGION:-us-east-1}.amazonaws.com 443
    Restart=always
    RestartSec=5

    [Install]
    WantedBy=multi-user.target
    VSOCK

    sed -i "s/\${AWS_REGION:-us-east-1}/${AWS_REGION:-us-east-1}/g" /etc/systemd/system/vsock-proxy.service
    systemctl daemon-reload
    systemctl enable --now vsock-proxy.service

    # ── Signal completion ──
    echo "Enclave-Guard bootstrap complete" | tee /var/log/enclave-guard-bootstrap.log
  USERDATA
}

# ── EC2 Instance ────────────────────────────────────────────────────────────

resource "aws_instance" "enclave_parent" {
  ami                    = var.ami_id != "" ? var.ami_id : data.aws_ami.al2023.id
  instance_type          = var.instance_type
  iam_instance_profile   = aws_iam_instance_profile.enclave_parent_profile.name
  key_name               = var.key_pair_name != "" ? var.key_pair_name : null
  vpc_security_group_ids = [aws_security_group.enclave_parent_sg.id]

  subnet_id = var.subnet_id != "" ? var.subnet_id : (
    length(data.aws_subnets.default) > 0 ? data.aws_subnets.default[0].ids[0] : null
  )

  # ── CRITICAL: Enable Nitro Enclaves ──
  enclave_options {
    enabled = true
  }

  # ── Storage ──
  root_block_device {
    volume_size           = 30
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true

    tags = {
      Name = "${var.project_name}-root-volume"
    }
  }

  # ── Metadata (IMDSv2 enforced for security) ──
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"   # IMDSv2 only
    http_put_response_hop_limit = 2            # Needed for containers
  }

  user_data                   = base64encode(local.user_data)
  user_data_replace_on_change = true

  monitoring = true  # Detailed CloudWatch monitoring

  tags = {
    Name    = "${var.project_name}-parent-instance"
    Purpose = "nitro-enclave-host"
  }

  lifecycle {
    # Prevent accidental destruction in production
    # prevent_destroy = true  # Uncomment in prod
    ignore_changes = [ami]
  }
}
