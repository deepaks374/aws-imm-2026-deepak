terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.30"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Environment = "Production-Demo"
      ManagedBy   = "Terraform"
      Project     = "CloudPulse-CNAPP-Showcase"
      Platform    = "Cortex-Cloud-SecOps"
    }
  }
}

variable "aws_region" {
  type        = string
  description = "AWS deployment region"
  default     = "ap-south-1"
}

variable "cluster_name" {
  type        = string
  description = "EKS Cluster identifier"
  default     = "cloudpulse-cnapp-eks"
}

variable "github_repository" {
  type        = string
  description = "GitHub repository in format owner/repo for GitHub Actions OIDC"
  default     = "deepaks374/aws-imm-2026-deepak:*"
}

data "aws_availability_zones" "available" {
  state = "available"
}

# ==============================================================================
# VPC and Networking Architecture
# Provides public subnets for load balancers & private subnets for EKS worker nodes
# ==============================================================================
resource "aws_vpc" "main" {
  cidr_block           = "10.120.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.cluster_name}-vpc"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.cluster_name}-igw"
  }
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(aws_vpc.main.cidr_block, 4, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name                                           = "${var.cluster_name}-public-${count.index}"
    "kubernetes.io/role/elb"                       = "1"
    "kubernetes.io/cluster/${var.cluster_name}"     = "shared"
  }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(aws_vpc.main.cidr_block, 4, count.index + 2)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name                                           = "${var.cluster_name}-private-${count.index}"
    "kubernetes.io/role/internal-elb"              = "1"
    "kubernetes.io/cluster/${var.cluster_name}"     = "shared"
  }
}

resource "aws_eip" "nat" {
  domain = "vpc"
  tags = {
    Name = "${var.cluster_name}-nat-eip"
  }
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id

  tags = {
    Name = "${var.cluster_name}-nat"
  }
  depends_on = [aws_internet_gateway.main]
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "${var.cluster_name}-public-rt"
  }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }

  tags = {
    Name = "${var.cluster_name}-private-rt"
  }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# ==============================================================================
# Elastic Container Registry (ECR)
# Target for container image builds and image security scans
# ==============================================================================
resource "aws_ecr_repository" "app_repo" {
  name                 = "cloudpulse-telemetry-engine"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name = "cloudpulse-telemetry-engine"
  }
}

# ==============================================================================
# EKS Cluster (Control Plane) - Version 1.28
# ==============================================================================
resource "aws_iam_role" "eks_control_plane" {
  name = "${var.cluster_name}-control-plane-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "eks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_control_plane.name
}

resource "aws_iam_role_policy_attachment" "eks_vpc_controller" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.eks_control_plane.name
}

resource "aws_security_group" "eks_cluster_sg" {
  name        = "${var.cluster_name}-cluster-sg"
  description = "Security group for EKS control plane"
  vpc_id      = aws_vpc.main.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.cluster_name}-cluster-sg"
  }
}

resource "aws_eks_cluster" "main" {
  name     = var.cluster_name
  role_arn = aws_iam_role.eks_control_plane.arn
  version  = "1.32"

  vpc_config {
    subnet_ids              = concat(aws_subnet.public[*].id, aws_subnet.private[*].id)
    security_group_ids      = [aws_security_group.eks_cluster_sg.id]
    endpoint_private_access = true
    endpoint_public_access  = true
  }

  access_config {
    authentication_mode                         = "API_AND_CONFIG_MAP"
    bootstrap_cluster_creator_admin_permissions = true
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_policy,
    aws_iam_role_policy_attachment.eks_vpc_controller
  ]
}

# ==============================================================================
# EKS Managed Node Group
# Provides worker node pool with proper IAM and egress for Cortex Agent DaemonSet
# ==============================================================================
resource "aws_iam_role" "eks_node_role" {
  name = "${var.cluster_name}-node-group-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "node_worker_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.eks_node_role.name
}

resource "aws_iam_role_policy_attachment" "node_cni_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.eks_node_role.name
}

resource "aws_iam_role_policy_attachment" "node_ecr_read" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.eks_node_role.name
}

# Launch template for worker nodes ensuring proper IMDS security posture testing
resource "aws_launch_template" "worker_nodes" {
  name_prefix   = "${var.cluster_name}-node-"
  instance_type = "t3.medium"

  # IaC Misconfiguration Vector:
  # http_endpoint enabled with http_tokens optional (allowing IMDSv1 SSRF/token scraping)
  # Detected by: Cortex IaC Security / Checkov / Bridgecrew
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"
    http_put_response_hop_limit = 2
  }

  monitoring {
    enabled = true
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "${var.cluster_name}-node"
    }
  }
}

resource "aws_eks_node_group" "main" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "${var.cluster_name}-workers"
  node_role_arn   = aws_iam_role.eks_node_role.arn
  subnet_ids      = aws_subnet.private[*].id

  scaling_config {
    desired_size = 2
    max_size     = 3
    min_size     = 1
  }

  launch_template {
    id      = aws_launch_template.worker_nodes.id
    version = "$Latest"
  }

  update_config {
    max_unavailable = 1
  }

  depends_on = [
    aws_iam_role_policy_attachment.node_worker_policy,
    aws_iam_role_policy_attachment.node_cni_policy,
    aws_iam_role_policy_attachment.node_ecr_read,
  ]
}

# ==============================================================================
# DSPM Vector: S3 Sensitive Data Bucket with Insecure Permissions
# Stores mock customer PII and transaction records for DSPM discovery & posture alerts
# ==============================================================================
resource "aws_s3_bucket" "dspm_vault" {
  bucket_prefix = "cloudpulse-restricted-data-vault-"
  force_destroy = true

  tags = {
    DataClassification = "RESTRICTED_CONFIDENTIAL"
    ComplianceScope    = "PCI-DSS_HIPAA"
  }
}

# Insecure IaC Vector: Bucket public access block disabled (simulates exposure)
resource "aws_s3_bucket_public_access_block" "dspm_vault_access" {
  bucket = aws_s3_bucket.dspm_vault.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_object" "synthetic_pii_upload" {
  bucket  = aws_s3_bucket.dspm_vault.id
  key     = "exports/financial_records_confidential.csv"
  content = <<EOF
account_id,primary_contact,ssn,credit_card,billing_address,limit_usd
ACC-9821,Sarah Jenkins,901-23-4567,4111-2222-3333-4444,"100 Market St, San Francisco, CA",50000
ACC-9822,David Kim,812-34-5678,5500-0000-0000-0004,"240 Wall St, New York, NY",75000
ACC-9823,Rachel Green,723-45-6789,3782-822463-10005,"500 Boylston St, Boston, MA",120000
EOF

  content_type = "text/csv"
}

# ==============================================================================
# CIEM Vector: Overprivileged Identity (IAM Role with Wildcard Action)
# Detected by: Cortex CIEM Identity Analyzer
# ==============================================================================
resource "aws_iam_role" "ciem_overprivileged_role" {
  name = "CloudPulse-CloudOps-OverprivilegedServiceRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
      }
    ]
  })
}

resource "aws_iam_policy" "wildcard_admin_access" {
  name        = "CloudPulse-Wildcard-Admin-Policy"
  description = "Excessive wildcard IAM policy violating least privilege"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:*",
          "iam:PassRole",
          "ec2:*"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ciem_attach" {
  role       = aws_iam_role.ciem_overprivileged_role.name
  policy_arn = aws_iam_policy.wildcard_admin_access.arn
}

data "aws_caller_identity" "current" {}
