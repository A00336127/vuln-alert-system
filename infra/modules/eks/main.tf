module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.0"

  cluster_name    = var.eks_cluster_name
  cluster_version = "1.31"

  vpc_id     = var.vpc_id
  subnet_ids = var.private_subnet_ids

  cluster_endpoint_public_access = true
  enable_irsa                    = true

  eks_managed_node_groups = {
    default = {
      instance_types = ["t3a.small"]
       capacity_type  = "ON_DEMAND"
      min_size       = 1
      max_size       = 2
      desired_size   = 1
    }
  }

  tags = { Project = var.project, Env = var.env }
}

output "cluster_name"                       { value = module.eks.cluster_name }
output "cluster_endpoint"                   { value = module.eks.cluster_endpoint }
output "oidc_provider_arn"                  { value = module.eks.oidc_provider_arn }
output "cluster_certificate_authority_data" { value = module.eks.cluster_certificate_authority_data }