# ==============================================================================
# CloudPulse Prerequisites & Integrations
# Configures:
# 1. IAM OIDC Identity Provider for EKS ServiceAccounts (IRSA)
# 2. GitHub Actions OIDC Provider & CI/CD Deployment Role
# ==============================================================================

# Fetch TLS certificate thumbprint for EKS OIDC
data "tls_certificate" "eks_oidc" {
  url = aws_eks_cluster.main.identity[0].oidc[0].issuer
}

# EKS OIDC Provider for IAM Roles for Service Accounts (IRSA)
resource "aws_iam_openid_connect_provider" "eks" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks_oidc.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.main.identity[0].oidc[0].issuer
}

# ==============================================================================
# GitHub Actions AWS OIDC Federation
# Allows passwordless, secure deployment from GitHub Actions into ECR and EKS
# ==============================================================================
data "tls_certificate" "github" {
  url = "https://token.actions.githubusercontent.com"
}

resource "aws_iam_openid_connect_provider" "github_actions" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.github.certificates[0].sha1_fingerprint]
}

resource "aws_iam_role" "github_actions_deployer" {
  name = "${var.cluster_name}-github-deployer-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.github_actions.arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringLike = {
            "token.actions.githubusercontent.com:sub" = "repo:${var.github_repository}"
          }
        }
      }
    ]
  })
}

resource "aws_iam_policy" "github_deployer_policy" {
  name        = "${var.cluster_name}-github-deployer-policy"
  description = "CI/CD pipeline permissions for GitHub Actions to push to ECR and deploy to EKS"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:GetRepositoryPolicy",
          "ecr:DescribeRepositories",
          "ecr:ListImages",
          "ecr:DescribeImages",
          "ecr:BatchGetImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload",
          "ecr:PutImage"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "eks:DescribeCluster",
          "eks:ListClusters",
          "eks:AccessKubernetesApi"
        ]
        Resource = "*"
      }
    ]
  })
}

# Grant GitHub Actions IAM Role full admin access entry in EKS 1.32
resource "aws_eks_access_entry" "github_actions" {
  cluster_name  = aws_eks_cluster.main.name
  principal_arn = aws_iam_role.github_actions_deployer.arn
  type          = "STANDARD"
}

resource "aws_eks_access_policy_association" "github_actions_cluster_admin" {
  cluster_name  = aws_eks_cluster.main.name
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
  principal_arn = aws_iam_role.github_actions_deployer.arn

  access_scope {
    type = "cluster"
  }
}

resource "aws_iam_role_policy_attachment" "github_deployer_attach" {
  role       = aws_iam_role.github_actions_deployer.name
  policy_arn = aws_iam_policy.github_deployer_policy.arn
}
