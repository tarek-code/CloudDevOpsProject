##############################
# 1️⃣ VPC Module
##############################
module "vpc" {
  source               = "terraform-aws-modules/vpc/aws"
  version              = "5.1.0"
  name                 = "${var.project_name}-vpc"
  cidr                 = var.vpc_cidr
  azs                  = var.vpc_azs
  public_subnets       = var.vpc_public_subnet_cidrs
  private_subnets      = var.vpc_private_subnet_cidrs
  enable_nat_gateway   = true
  single_nat_gateway   = var.vpc_single_nat_gateway
  enable_vpn_gateway   = var.vpc_enable_vpn_gateway
  enable_dns_hostnames = var.vpc_enable_dns_hostnames
  create_igw           = var.vpc_enable_internet_gateway

  public_dedicated_network_acl = true
  public_inbound_acl_rules = [
    { rule_number = 100, rule_action = "allow", from_port = var.ssh_port, to_port = var.ssh_port, protocol = var.nacl_tcp_protocol, cidr_block = var.allowed_cidr },
    { rule_number = 110, rule_action = "allow", from_port = var.jenkins_port, to_port = var.jenkins_port, protocol = var.nacl_tcp_protocol, cidr_block = var.allowed_cidr },
    { rule_number = 120, rule_action = "allow", from_port = var.https_port, to_port = var.https_port, protocol = var.nacl_tcp_protocol, cidr_block = var.allowed_cidr },
    { rule_number = 125, rule_action = "allow", from_port = 80, to_port = 80, protocol = var.nacl_tcp_protocol, cidr_block = "0.0.0.0/0" }, # HTTP for ALB in public subnet
    # Return traffic for outbound connections (e.g. yum, S3) - required for EC2 in public subnet to reach internet
    { rule_number = 130, rule_action = "allow", from_port = 1024, to_port = 65535, protocol = var.nacl_tcp_protocol, cidr_block = "0.0.0.0/0" },
  ]
  public_outbound_acl_rules = [
    { rule_number = 100, rule_action = "allow", from_port = var.egress_from_port, to_port = var.egress_to_port, protocol = var.egress_protocol, cidr_block = var.egress_cidr }
  ]

  public_subnet_tags = {
    "kubernetes.io/role/elb"                        = "1"
    "kubernetes.io/cluster/${var.eks_cluster_name}" = "shared"
  }
  private_subnet_tags = {
    "kubernetes.io/role/internal-elb"               = "1"
    "kubernetes.io/cluster/${var.eks_cluster_name}" = "shared"
  }

  tags = {
    Name = "${var.project_name}-vpc"
  }
}


##############################
# 3️⃣ Security Group Module
##############################
module "security_group" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "5.1.0"
  name    = "${var.project_name}-jenkins-security-group"
  vpc_id  = module.vpc.vpc_id

  ingress_with_cidr_blocks = [
    {
      from_port   = var.jenkins_port
      to_port     = var.jenkins_port
      protocol    = var.sg_ingress_protocol
      cidr_blocks = var.allowed_cidr
      description = "Allow Jenkins from any IP"
    },
    {
      from_port   = var.ssh_port
      to_port     = var.ssh_port
      protocol    = var.sg_ingress_protocol
      cidr_blocks = var.allowed_cidr
      description = "Allow SSH from any IP"
    }
  ]

  egress_with_cidr_blocks = [
    {
      from_port   = var.egress_from_port
      to_port     = var.egress_to_port
      protocol    = var.egress_protocol
      cidr_blocks = var.egress_cidr
      description = "Allow all outbound"
    }
  ]

  tags = {
    Name = "${var.project_name}-jenkins-security-group"
  }
}


##############################
# search for the latest amazon linux 2 ami
##############################
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = var.ami_owners

  filter {
    name   = "name"
    values = [var.ami_name_filter]
  }
}
##############################
# 4️⃣ IAM role for Jenkins EC2 (ECR push + EKS describe)
##############################
data "aws_caller_identity" "current" {}

resource "aws_iam_role" "jenkins_ec2" {
  name = "${var.project_name}-jenkins-ec2-role"

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

resource "aws_iam_role_policy" "jenkins_ecr_eks" {
  name = "${var.project_name}-jenkins-ecr-eks"
  role = aws_iam_role.jenkins_ec2.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ECRLoginAndPush"
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken"
        ]
        Resource = "*"
      },
      {
        Sid    = "ECRRepository"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:PutImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload"
        ]
        Resource = "arn:aws:ecr:${var.aws_region}:${data.aws_caller_identity.current.account_id}:repository/*"
      },
      {
        Sid    = "EKSDescribe"
        Effect = "Allow"
        Action = [
          "eks:DescribeCluster"
        ]
        Resource = "arn:aws:eks:${var.aws_region}:${data.aws_caller_identity.current.account_id}:cluster/*"
      },
      {
        Sid    = "ELBAndEC2DescribeForDiagnostics"
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:DescribeLoadBalancers",
          "elasticloadbalancing:DescribeTargetGroups",
          "elasticloadbalancing:DescribeListeners",
          "ec2:DescribeRouteTables",
          "ec2:DescribeSubnets",
          "ec2:DescribeSecurityGroups"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "jenkins_ec2" {
  name = "${var.project_name}-jenkins-ec2-profile"
  role = aws_iam_role.jenkins_ec2.name
}

##############################
# ECR repository for app image (Jenkins pushes here)
##############################
resource "aws_ecr_repository" "app" {
  name                 = var.ecr_repository_name
  image_tag_mutability = "MUTABLE"
  force_delete         = true # Allow destroy even when repository has images
}

##############################
# 5️⃣ Jenkins EC2 Module
##############################
module "jenkins_ec2" {
  source                      = "terraform-aws-modules/ec2-instance/aws"
  version                     = "6.0.0"
  name                        = "${var.project_name}-jenkins-ec2"
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = var.jenkins_instance_type
  subnet_id                   = module.vpc.public_subnets[0]
  associate_public_ip_address = var.jenkins_associate_public_ip
  vpc_security_group_ids      = [module.security_group.security_group_id]
  key_name                    = var.jenkins_key_name
  iam_instance_profile        = aws_iam_instance_profile.jenkins_ec2.name
  tags = {
    service = var.jenkins_ansible_tag
  }
}

##############################
# 6️⃣ EKS Module
##############################
module "eks" {
  source                 = "terraform-aws-modules/eks/aws"
  version                = "21.0.0"
  name                   = var.eks_cluster_name
  kubernetes_version     = var.eks_cluster_version
  vpc_id                 = module.vpc.vpc_id
  subnet_ids             = concat(module.vpc.public_subnets, module.vpc.private_subnets)
  endpoint_public_access = true
  tags = {
    Name = var.eks_cluster_name
  }

  # Allow Jenkins EC2 to reach EKS API on 443 (v21 uses security_group_additional_rules)
  security_group_additional_rules = {
    ingress_from_jenkins = {
      description              = "Allow Jenkins EC2 to reach EKS API"
      protocol                 = "tcp"
      from_port                = 443
      to_port                  = 443
      type                     = "ingress"
      source_security_group_id = module.security_group.security_group_id
    }
  }

  # Grant Jenkins EC2 IAM role access to the cluster (for Helm/kubectl from Ansible and pipelines)
  access_entries = {
    jenkins_ec2 = {
      principal_arn = aws_iam_role.jenkins_ec2.arn
      type          = "STANDARD"
      policy_associations = {
        cluster_admin = {
          policy_arn = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
          access_scope = {
            type = "cluster"
          }
        }
      }
    }
  }

  # Fargate requires private subnets
  fargate_profiles = {
    fargate_profile = {
      name       = "${var.project_name}-fargate-profile"
      subnet_ids = module.vpc.private_subnets
      selectors  = [{ namespace = "kube-system" }, { namespace = "default" }, { namespace = "ivolve" }, { namespace = "argocd" }]
      tags = {
        Name = "${var.project_name}-fargate-profile"
      }
    }
  }
}

# Install CoreDNS addon (required for DNS resolution in EKS, especially on Fargate)
resource "aws_eks_addon" "coredns" {
  cluster_name                = module.eks.cluster_name
  addon_name                  = "coredns"
  addon_version               = "v1.11.1-eksbuild.4" # Match EKS 1.30; update if needed
  resolve_conflicts_on_update = "OVERWRITE"
  tags = {
    Name = "${var.project_name}-coredns-addon"
  }
  timeouts {
    create = "30m" # Fargate clusters can take longer for CoreDNS to become ACTIVE
    update = "30m"
    delete = "20m"
  }
}

locals {
  # Use the standard OIDC issuer format (not dual-stack) for IAM trust policies
  # Kubernetes uses: oidc.eks.us-east-1.amazonaws.com/id/...
  # Extract the ID from the cluster OIDC issuer URL
  oidc_issuer_url = module.eks.cluster_oidc_issuer_url
  oidc_issuer_id  = regex("id/([^/]+)", local.oidc_issuer_url)[0]
  # Standard format that Kubernetes actually uses
  oidc_issuer       = "oidc.eks.${var.aws_region}.amazonaws.com/id/${local.oidc_issuer_id}"
  oidc_provider_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${local.oidc_issuer}"
}

# AWS Load Balancer Controller IAM (IRSA) – policy, role, OIDC; Ansible only applies ServiceAccount.
# Uses EKS module outputs instead of a separate aws_eks_cluster data source so a single apply works on a fresh account.
# EKS must still be created in the same apply (module.eks above).
# Note: OIDC provider may already exist from EKS cluster creation; Terraform will reference it.
# Use standard format (oidc.eks...) that Kubernetes actually uses for IRSA tokens
resource "aws_iam_openid_connect_provider" "eks" {
  url             = "https://${local.oidc_issuer}"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["9e99a48a9960b14926bb7f3b02e22da2b0ab7280"]

  # Prevent errors if provider already exists (created by EKS or previous run)
  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_iam_policy" "alb_controller" {
  name        = "AWSLoadBalancerControllerIAMPolicy"
  description = "IAM policy for AWS Load Balancer Controller"
  policy      = file("${path.module}/alb-controller-iam-policy.json")
}

resource "aws_iam_role" "alb_controller" {
  name = "AWSLoadBalancerControllerRole"

  # Trust policy for IRSA: allows ALB controller ServiceAccount to assume this role
  # Uses standard OIDC issuer format (oidc.eks...) that Kubernetes actually uses for IRSA tokens
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = local.oidc_provider_arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "${local.oidc_issuer}:aud" = "sts.amazonaws.com"
            "${local.oidc_issuer}:sub" = "system:serviceaccount:kube-system:aws-load-balancer-controller"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "alb_controller" {
  policy_arn = aws_iam_policy.alb_controller.arn
  role       = aws_iam_role.alb_controller.name
}

##############################
# 7️⃣ SNS Module
##############################

module "sns_alerts" {
  source  = "terraform-aws-modules/sns/aws"
  version = "6.2.1"

  name = var.sns_alert_topic_name

  subscriptions = {
    email_alert = {
      protocol = var.sns_subscription_protocol
      endpoint = var.sns_alert_email
    }
  }
}

##############################
# 8️⃣ CloudWatch Module
##############################
resource "aws_cloudwatch_metric_alarm" "jenkins_cpu" {
  alarm_name          = var.cloudwatch_alarm_name
  comparison_operator = var.cloudwatch_alarm_comparison_operator
  evaluation_periods  = var.cloudwatch_alarm_evaluation_periods
  metric_name         = var.cloudwatch_alarm_metric_name
  namespace           = var.cloudwatch_alarm_namespace
  period              = var.cloudwatch_alarm_period
  statistic           = var.cloudwatch_alarm_statistic
  threshold           = var.cloudwatch_alarm_threshold
  alarm_description   = var.cloudwatch_alarm_description
  alarm_actions       = [module.sns_alerts.topic_arn]
  dimensions = {
    InstanceId = module.jenkins_ec2.id
  }
}
