output "aws_region" {
  description = "Target AWS deployment region"
  value       = var.aws_region
}

output "eks_cluster_name" {
  description = "Name of the provisioned EKS cluster"
  value       = aws_eks_cluster.main.name
}

output "eks_cluster_endpoint" {
  description = "API Server Endpoint for EKS"
  value       = aws_eks_cluster.main.endpoint
}

output "ecr_repository_url" {
  description = "ECR Repository URL for container image push"
  value       = aws_ecr_repository.app_repo.repository_url
}

output "github_actions_role_arn" {
  description = "IAM Role ARN for GitHub Actions OIDC federation"
  value       = aws_iam_role.github_actions_deployer.arn
}

output "dspm_vault_bucket_name" {
  description = "S3 Bucket storing sensitive PII/financial records for DSPM evaluation"
  value       = aws_s3_bucket.dspm_vault.id
}

output "configure_kubectl_command" {
  description = "Command to configure local kubeconfig for the cluster"
  value       = "aws eks --region ${var.aws_region} update-kubeconfig --name ${aws_eks_cluster.main.name}"
}
