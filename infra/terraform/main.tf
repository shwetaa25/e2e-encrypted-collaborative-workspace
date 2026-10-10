# terraform/main.tf
# ─────────────────────────────────────────────────────────
# Terraform configuration for cloud infrastructure.
# Provider: AWS (swap to GCP/Azure by changing provider block)
#
# Provisions:
#   - VPC with public/private subnets
#   - EKS cluster (Kubernetes)
#   - RDS PostgreSQL (managed, encrypted at rest)
#   - ECR (container registry, alternative to GHCR)
#
# Usage:
#   terraform init
#   terraform plan -var="db_password=<secure-password>"
#   terraform apply
# ─────────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  # Store state remotely (uncomment for team use)
  # backend "s3" {
  #   bucket = "your-terraform-state-bucket"
  #   key    = "encrypted-workspace/terraform.tfstate"
  #   region = "us-east-1"
  # }
}

provider "aws" {
  region = var.aws_region
}

# ── Variables ─────────────────────────────────────────────

variable "aws_region"    { default = "us-east-1" }
variable "project_name"  { default = "encrypted-workspace" }
variable "environment"   { default = "production" }
variable "db_password"   { sensitive = true }
variable "k8s_version"   { default = "1.29" }

locals {
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# ── VPC ───────────────────────────────────────────────────

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = merge(local.common_tags, { Name = "${var.project_name}-vpc" })
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.${count.index}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags = merge(local.common_tags, { Name = "${var.project_name}-private-${count.index}" })
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.${count.index + 10}.0/24"
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true
  tags = merge(local.common_tags, { Name = "${var.project_name}-public-${count.index}" })
}

data "aws_availability_zones" "available" {}

# ── EKS Cluster ───────────────────────────────────────────

resource "aws_eks_cluster" "main" {
  name     = var.project_name
  version  = var.k8s_version
  role_arn = aws_iam_role.eks_cluster.arn

  vpc_config {
    subnet_ids = aws_subnet.private[*].id
    endpoint_private_access = true
    endpoint_public_access  = true
  }

  tags = local.common_tags

  depends_on = [aws_iam_role_policy_attachment.eks_cluster_policy]
}

resource "aws_eks_node_group" "workers" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "workers"
  node_role_arn   = aws_iam_role.eks_node.arn
  subnet_ids      = aws_subnet.private[*].id

  instance_types = ["t3.medium"]

  scaling_config {
    desired_size = 2
    min_size     = 2
    max_size     = 6
  }

  tags = local.common_tags
  depends_on = [
    aws_iam_role_policy_attachment.eks_worker_node_policy,
    aws_iam_role_policy_attachment.eks_cni_policy,
  ]
}

# ── IAM roles for EKS (required) ─────────────────────────

resource "aws_iam_role" "eks_cluster" {
  name = "${var.project_name}-eks-cluster"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Action = "sts:AssumeRole", Effect = "Allow",
      Principal = { Service = "eks.amazonaws.com" } }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster.name
}

resource "aws_iam_role" "eks_node" {
  name = "${var.project_name}-eks-node"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Action = "sts:AssumeRole", Effect = "Allow",
      Principal = { Service = "ec2.amazonaws.com" } }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_worker_node_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.eks_node.name
}

resource "aws_iam_role_policy_attachment" "eks_cni_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.eks_node.name
}

# ── RDS PostgreSQL (encrypted at rest) ───────────────────

resource "aws_db_subnet_group" "postgres" {
  name       = "${var.project_name}-db"
  subnet_ids = aws_subnet.private[*].id
  tags       = local.common_tags
}

resource "aws_db_instance" "postgres" {
  identifier        = var.project_name
  engine            = "postgres"
  engine_version    = "16.2"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  storage_type      = "gp3"

  db_name  = "encryptedws"
  username = "postgres"
  password = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.postgres.name
  vpc_security_group_ids = [aws_security_group.rds.id]

  # Encryption at rest (defence in depth — documents are also app-level encrypted)
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn

  backup_retention_period = 7
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:04:00-sun:05:00"

  skip_final_snapshot = false
  final_snapshot_identifier = "${var.project_name}-final"

  tags = local.common_tags
}

resource "aws_kms_key" "rds" {
  description             = "KMS key for RDS encryption — ${var.project_name}"
  deletion_window_in_days = 7
  tags                    = local.common_tags
}

resource "aws_security_group" "rds" {
  name   = "${var.project_name}-rds"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [] # Filled in by EKS node SG reference
    description     = "Allow PostgreSQL from EKS nodes only"
  }

  tags = local.common_tags
}

# ── Outputs ───────────────────────────────────────────────

output "eks_cluster_endpoint" {
  value = aws_eks_cluster.main.endpoint
}

output "rds_endpoint" {
  value     = aws_db_instance.postgres.endpoint
  sensitive = true
}

output "database_url" {
  value     = "postgresql+asyncpg://postgres:${var.db_password}@${aws_db_instance.postgres.endpoint}/encryptedws"
  sensitive = true
}
