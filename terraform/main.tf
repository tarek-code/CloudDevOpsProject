##############################
# 1️⃣ VPC Module
##############################
module "vpc" {
  source                  = "terraform-aws-modules/vpc/aws"
  version                 = "5.1.0"
  name                    = "${var.project_name}-vpc"
  cidr                    = var.vpc_cidr
  azs                     = var.vpc_azs
  public_subnets          = var.vpc_public_subnet_cidrs
  enable_nat_gateway      = var.vpc_enable_nat_gateway
  enable_vpn_gateway      = var.vpc_enable_vpn_gateway
  enable_dns_hostnames    = var.vpc_enable_dns_hostnames
  enable_internet_gateway = var.vpc_enable_internet_gateway

  public_inbound_acl_rules = [
    { rule_number = 100, rule_action = "allow", from_port = var.ssh_port, to_port = var.ssh_port, protocol = var.nacl_tcp_protocol, cidr_block = var.allowed_cidr },
    { rule_number = 110, rule_action = "allow", from_port = var.jenkins_port, to_port = var.jenkins_port, protocol = var.nacl_tcp_protocol, cidr_block = var.allowed_cidr },
    { rule_number = 120, rule_action = "allow", from_port = var.https_port, to_port = var.https_port, protocol = var.nacl_tcp_protocol, cidr_block = var.allowed_cidr },
  ]
  public_outbound_acl_rules = [
    { rule_number = 100, rule_action = "allow", from_port = var.egress_from_port, to_port = var.egress_to_port, protocol = var.egress_protocol, cidr_block = var.egress_cidr }
  ]

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
      cidr_blocks = [var.allowed_cidr]
      description = "Allow Jenkins from any IP"
    },
    {
      from_port   = var.ssh_port
      to_port     = var.ssh_port
      protocol    = var.sg_ingress_protocol
      cidr_blocks = [var.allowed_cidr]
      description = "Allow SSH from any IP"
    }
  ]

  egress_with_cidr_blocks = [
    {
      from_port   = var.egress_from_port
      to_port     = var.egress_to_port
      protocol    = var.egress_protocol
      cidr_blocks = [var.egress_cidr]
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
# 4️⃣ Jenkins EC2 Module
##############################
module "jenkins-ec2" {
  source                      = "terraform-aws-modules/ec2-instance/aws"
  version                     = "5.1.0"
  name                        = "${var.project_name}-jenkins-ec2"
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = var.jenkins_instance_type
  subnet_id                   = module.vpc.public_subnets[0]
  associate_public_ip_address = var.jenkins_associate_public_ip
  vpc_security_group_ids      = [module.security_group.security_group_id]
  key_name                    = var.jenkins_key_name
  tags = {
    service = var.jenkins_ansible_tag
  }
}

##############################
# 5️⃣ EKS Module
##############################
module "eks" {
  source          = "terraform-aws-modules/eks/aws"
  version         = "20.1.0"
  cluster_name    = var.eks_cluster_name
  cluster_version = var.eks_cluster_version
  vpc_id          = module.vpc.vpc_id
  subnet_ids      = module.vpc.public_subnets
  tags = {
    Name = var.eks_cluster_name
  }

  fargate_profiles = {
    fargate_profile = {
      name       = "${var.project_name}-fargate-profile"
      subnet_ids = module.vpc.public_subnets
      tags = {
        Name = "${var.project_name}-fargate-profile"
      }
    }
  }
}


##############################
# 6️⃣ SNS Module
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
# 7️⃣ CloudWatch Module
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
    InstanceId = module["jenkins-ec2"].id
  }
}
