##############################
# 1️⃣ VPC Module
##############################
module "vpc" {
  source                  = "terraform-aws-modules/vpc/aws"
  version                 = "5.1.0"
  name                    = "ivolve-vpc"
  cidr                    = "10.0.0.0/16"
  azs                     = ["us-east-1a", "us-east-1b"]
  public_subnets          = ["10.0.1.0/24", "10.0.2.0/24"]
  enable_nat_gateway      = false
  enable_vpn_gateway      = false
  enable_dns_hostnames    = true
  enable_internet_gateway = true

  # Network ACL for public subnets (no separate NACL module in registry; VPC module supports it)
  public_inbound_acl_rules = [
    { rule_number = 100, rule_action = "allow", from_port = 22, to_port = 22, protocol = "6", cidr_block = "0.0.0.0/0" },
    { rule_number = 110, rule_action = "allow", from_port = 8080, to_port = 8080, protocol = "6", cidr_block = "0.0.0.0/0" },
    { rule_number = 120, rule_action = "allow", from_port = 443, to_port = 443, protocol = "6", cidr_block = "0.0.0.0/0" },
  ]
  public_outbound_acl_rules = [
    { rule_number = 100, rule_action = "allow", from_port = 0, to_port = 0, protocol = "-1", cidr_block = "0.0.0.0/0" }
  ]

  tags = {
    Name = "ivolve-vpc"
  }
}


##############################
# 3️⃣ Security Group Module
##############################
module "security_group" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "5.1.0"
  name    = "jenkins-security-group"
  vpc_id  = module.vpc.vpc_id

  ingress_with_cidr_blocks = [
    {
      from_port   = 8080 # Jenkins default port
      to_port     = 8080
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"] # <-- غيرها بالـ IP بتاعك
      description = "Allow Jenkins from any IP"
    },
    {
      from_port   = 22 # SSH
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
      description = "Allow SSH from any IP"
    }
  ]

  egress_with_cidr_blocks = [
    {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
      description = "Allow all outbound"
    }
  ]

  tags = {
    Name = "jenkins-security-group"
  }
}


##############################
# search for the latest amazon linux 2 ami
##############################
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}
##############################
# 4️⃣ Jenkins EC2 Module
##############################
module "jenkins-ec2" {
  source                      = "terraform-aws-modules/ec2-instance/aws"
  version                     = "5.1.0"
  name                        = "jenkins-ec2"
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = "t3.medium"
  subnet_id                   = module.vpc.public_subnets[0]
  associate_public_ip_address = true # <-- مهم
  vpc_security_group_ids      = [module.security_group.security_group_id]
  key_name                    = "jenkins_key"
  tags = {
    service = "jenkins"
  }
}

##############################
# 5️⃣ EKS Module
##############################
module "eks" {
  source          = "terraform-aws-modules/eks/aws"
  version         = "20.1.0"
  cluster_name    = "ivolve-eks"
  cluster_version = "1.27"
  vpc_id          = module.vpc.vpc_id
  subnet_ids      = module.vpc.public_subnets # pods هتشتغل على public subnet
  tags = {
    Name = "ivolve-eks"
  }

  fargate_profiles = {
    fargate_profile = {
      name       = "fargate-profile"
      subnet_ids = module.vpc.public_subnets
      tags = {
        Name = "fargate-profile"
      }
    }
  }
}


##############################
# 6️⃣ SNS Module
##############################

module "sns_alerts" {
  source  = "terraform-aws-modules/sns/aws"
  version = "4.0.0"

  name = "jenkins-alerts-topic"

  subscriptions = {
    email_alert = {
      protocol = "email"
      endpoint = "tarekdel314@gmail.com"
    }
  }
}

##############################
# 7️⃣ CloudWatch Module
##############################
resource "aws_cloudwatch_metric_alarm" "jenkins_cpu" {
  alarm_name          = "jenkins-ec2-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 70 # 70% CPU
  alarm_description   = "CPU > 70% for Jenkins EC2"
  alarm_actions       = [module.sns_alerts.sns_topic_arn] # Optional: SNS topic ARN
  dimensions = {
    InstanceId = module["jenkins-ec2"].id
  }
}
