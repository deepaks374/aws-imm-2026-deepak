# ==============================================================================
# Additional Insecure Cloud Infrastructure & Resource Definitions
# Designed specifically for Palo Alto Networks Cortex Cloud (CSPM/CIEM/DSPM)
# Detection & Policy Compliance Testing
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. Unencrypted S3 Bucket with Public Write & Logging Disabled
# Detected by: Cortex Cloud Posture (CSPM) - CIS AWS Benchmark
# ------------------------------------------------------------------------------
resource "aws_s3_bucket" "unencrypted_public_logs" {
  bucket_prefix = "cloudpulse-unencrypted-logs-"
  force_destroy = true

  tags = {
    Name        = "cloudpulse-unencrypted-logs"
    Environment = "Production-Demo"
    Compliance  = "Non-Compliant"
  }
}

resource "aws_s3_bucket_public_access_block" "unencrypted_public_logs_exposure" {
  bucket = aws_s3_bucket.unencrypted_public_logs.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# ------------------------------------------------------------------------------
# 2. Open Security Group Permitting All Inbound Traffic (0.0.0.0/0 on SSH & DB)
# Detected by: Cortex CSPM Network Security Posture
# ------------------------------------------------------------------------------
resource "aws_security_group" "overly_permissive_ingress" {
  name        = "cloudpulse-insecure-wide-open-sg"
  description = "Insecure Security Group permitting unrestricted 0.0.0.0/0 ingress"
  vpc_id      = aws_vpc.main.id

  # Insecure: Open SSH port 22 from anywhere
  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Insecure: Open Database port 5432 from anywhere
  ingress {
    description = "Postgres from anywhere"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Insecure: Open RDP port 3389 from anywhere
  ingress {
    description = "RDP from anywhere"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "cloudpulse-insecure-wide-open-sg"
  }
}

# ------------------------------------------------------------------------------
# 3. Unencrypted EBS Storage Volume
# Detected by: Cortex CSPM Storage Encryption Policies
# ------------------------------------------------------------------------------
resource "aws_ebs_volume" "unencrypted_diagnostic_volume" {
  availability_zone = data.aws_availability_zones.available.names[0]
  size              = 20
  encrypted         = false # Insecure: Encryption disabled

  tags = {
    Name = "cloudpulse-unencrypted-diagnostic-ebs"
  }
}

# ------------------------------------------------------------------------------
# 4. Overprivileged IAM User with Static Insecure Access Keys
# Detected by: Cortex CIEM / IAM Posture & Secret Analyzer
# ------------------------------------------------------------------------------
resource "aws_iam_user" "legacy_service_operator" {
  name = "cloudpulse-legacy-operator-user"

  tags = {
    Role = "MachineIdentity"
  }
}

resource "aws_iam_user_policy" "legacy_full_access" {
  name = "CloudPulse-Legacy-FullAccess"
  user = aws_iam_user.legacy_service_operator.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_access_key" "legacy_operator_key" {
  user = aws_iam_user.legacy_service_operator.name
}
