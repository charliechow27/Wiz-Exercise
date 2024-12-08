#### PROVIDER

provider "aws" {
  region = "eu-west-2"
}

#### CONFIGURE VPC

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.16.0"

  name = "wiz-exercise-vpc"
  cidr = "10.0.0.0/16"

  enable_dns_hostnames = true
  enable_dns_support   = true

  azs             = ["eu-west-2a", "eu-west-2b", "eu-west-2c"]
  private_subnets = ["10.0.0.0/24", "10.0.1.0/24"]
  public_subnets  = ["10.0.2.0/24", "10.0.3.0/24"]

  tags = {
    "Name" = "wiz-exercise-vpc"
  }

  public_subnet_tags = {
    "Name"                   = "PublicSubnet"
    "Kubernetes.io/role/elb" = "1"
  }

  private_subnet_tags = {
    "Name"                   = "PrivateSubnet"
    "Kubernetes.io/role/elb" = "1"
  }

  map_public_ip_on_launch = true
}


# Create Route Table
resource "aws_route_table" "public_route_table" {
  vpc_id = module.vpc.vpc_id
  tags = {
    Name = "Public-Route-Table"
  }
}

#### CONFIGURE EC2

# EC2 instance for the database server
resource "aws_instance" "db_instance" {
  ami           = "ami-0381be2d3766c7e4e"
  instance_type = "t2.medium"
  subnet_id     = module.vpc.public_subnets[0]
  key_name      = "wizkey"

  security_groups = [aws_security_group.db_sg.id]

  iam_instance_profile = aws_iam_instance_profile.ec2_instance_profile.name

  tags = {
    Name = "DB-Instance"
  }

   lifecycle {
    ignore_changes = [
      security_groups,
    ]
  }
}

# Security group for DB instance
resource "aws_security_group" "db_sg" {
  name_prefix = "db-sg-"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] 
  }

  ingress {
    from_port   = 27017
    to_port     = 27017
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "ec2-role-for-db"
  role = aws_iam_role.ec2_role.name
}

# IAM role configuration

resource "aws_iam_role" "ec2_role" {
  name               = "ec2-role-for-db"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role_policy.json
}

data "aws_iam_policy_document" "ec2_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "ec2_policy" {
  name = "ec2-policy-for-db"
  role = aws_iam_role.ec2_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "ec2:*"
        Effect   = "Allow"
        Resource = "*"
      },
      {
        Action   = "s3:PutObject"
        Effect   = "Allow"
        Resource = "arn:aws:s3:::${aws_s3_bucket.db_backups.bucket}/*"
      },
      {
        Action = "s3:GetObject"
        Effect = "Allow"
        Resource = "arn:aws:s3:::${aws_s3_bucket.db_backups.bucket}/*"
      }
    ]
  })
}



#### CONFIGURE S3

resource "aws_s3_bucket" "db_backups" {
  bucket = "wiz-exercise-db-backup-1234"
}

resource "aws_s3_bucket_versioning" "db_backup_versioning" {
  bucket = aws_s3_bucket.db_backups.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "db_backups_block" {
  bucket = aws_s3_bucket.db_backups.bucket

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

#is this needed?
resource "aws_s3_bucket_policy" "db_backups_policy" {
  bucket = aws_s3_bucket.db_backups.bucket
  policy = jsonencode({
    Version : "2012-10-17",
    Statement : [
      {
        Action : [
          "s3:Get*"
        ],
        Effect : "Allow",
        Resource = "arn:aws:s3:::${aws_s3_bucket.db_backups.bucket}/*"
        Principal : "*"
      }
    ]
  })
}

#### CONFIGURE EKS

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "20.31.0"

  cluster_name                   = "web-app-cluster"
  cluster_version                = "1.31"
  cluster_endpoint_public_access = true

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.public_subnets

  eks_managed_node_groups = {
    managed_group = {
      name           = "managed-group"
      instance_types = ["t3.medium"] # Instance type for the nodes
      desired_size   = 2             # Desired capacity
      max_size       = 3             # Maximum capacity
      min_size       = 1             # Minimum capacity
    }
  }

  cluster_addons = {
    coredns = {
      most_recent = true
    }
    kube-proxy = {
      most_recent = true
    }
    vpc-cni = {
      most_recent = true
    }
  }

  tags = {
    Name = "wiz-cluster"
  }

  authentication_mode = "API"
}

# Create IAM Policy
data "aws_iam_policy_document" "eks_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
  statement {
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::120569644156:user/charlie"]
    }

    actions = ["sts:AssumeRole"]
  }

  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

# Attach Policy to Role 
resource "aws_iam_role" "eks_cluster" {
  name               = "eks_cluster"
  assume_role_policy = data.aws_iam_policy_document.eks_assume_role.json
}

# Attach AmazonEKSClusterPolicy to the role
resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster.name
}

# Attach AmazonEKSServicePolicy to the role
resource "aws_iam_role_policy_attachment" "eks_service_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSServicePolicy"
  role       = aws_iam_role.eks_cluster.name
}

# Configure Security Group to enable communication with EKS control plane
resource "aws_security_group" "eks_worker_sg" {
  vpc_id = module.vpc.vpc_id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 10250
    to_port     = 10250
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "eks-worker-sg"
  }
}

#### CONFIGURE AWS CONFIG




