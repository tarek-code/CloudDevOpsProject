# -----------------------------------------------------------------------------
# AWS / Provider
# -----------------------------------------------------------------------------
variable "aws_region" {
  type        = string
  description = "AWS region"
  default     = "us-east-1"
}

variable "aws_profile" {
  type        = string
  description = "AWS CLI profile name (leave null/empty when using Terraform Cloud or env credentials)"
  default     = null
}

variable "aws_account_id" {
  type        = string
  description = "AWS account ID"
  default     = "123456789012"
}

variable "AWS_ACCESS_KEY_ID" {
  type        = string
  sensitive   = true
  description = "AWS access key (or set in Terraform Cloud)"
}

variable "AWS_SECRET_ACCESS_KEY" {
  type        = string
  sensitive   = true
  description = "AWS secret key (or set in Terraform Cloud)"
}

# -----------------------------------------------------------------------------
# Project / Naming
# -----------------------------------------------------------------------------
variable "project_name" {
  type        = string
  description = "Project name used for resource naming"
  default     = "ivolve"
}

# -----------------------------------------------------------------------------
# VPC
# -----------------------------------------------------------------------------
variable "vpc_cidr" {
  type        = string
  description = "CIDR block for VPC"
  default     = "10.0.0.0/16"
}

variable "vpc_azs" {
  type        = list(string)
  description = "Availability zones for subnets"
  default     = ["us-east-1a", "us-east-1b"]
}

variable "vpc_public_subnet_cidrs" {
  type        = list(string)
  description = "CIDR blocks for public subnets (one per AZ)"
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "vpc_private_subnet_cidrs" {
  type        = list(string)
  description = "CIDR blocks for private subnets (one per AZ); required for EKS Fargate"
  default     = ["10.0.11.0/24", "10.0.12.0/24"]
}

variable "vpc_enable_nat_gateway" {
  type        = bool
  description = "Enable NAT gateway for private subnets (overridden to true when using Fargate)"
  default     = false
}

variable "vpc_single_nat_gateway" {
  type        = bool
  description = "Use a single NAT gateway for all private subnets (cheaper)"
  default     = true
}

variable "vpc_enable_vpn_gateway" {
  type        = bool
  description = "Enable VPN gateway"
  default     = false
}

variable "vpc_enable_dns_hostnames" {
  type        = bool
  description = "Enable DNS hostnames in VPC"
  default     = true
}

variable "vpc_enable_internet_gateway" {
  type        = bool
  description = "Enable internet gateway"
  default     = true
}

variable "nacl_tcp_protocol" {
  type        = string
  description = "NACL protocol number for TCP (6)"
  default     = "6"
}

# Allowed CIDR for ingress (e.g. 0.0.0.0/0 or your IP)
variable "allowed_cidr" {
  type        = string
  description = "CIDR allowed for SSH and Jenkins ingress"
  default     = "0.0.0.0/0"
}

variable "ssh_port" {
  type        = number
  description = "SSH port for security group and VPC NACL"
  default     = 22
}

variable "jenkins_port" {
  type        = number
  description = "Jenkins UI port for security group and VPC NACL"
  default     = 8080
}

variable "https_port" {
  type        = number
  description = "HTTPS port for VPC NACL"
  default     = 443
}

# Egress "allow all" (from_port/to_port 0, protocol -1)
variable "egress_from_port" {
  type        = number
  description = "Egress from_port (0 for all)"
  default     = 0
}

variable "egress_to_port" {
  type        = number
  description = "Egress to_port (0 for all)"
  default     = 0
}

variable "egress_protocol" {
  type        = string
  description = "Egress protocol (-1 for all)"
  default     = "-1"
}

variable "egress_cidr" {
  type        = string
  description = "CIDR for egress (usually 0.0.0.0/0)"
  default     = "0.0.0.0/0"
}

# -----------------------------------------------------------------------------
# Jenkins EC2
# -----------------------------------------------------------------------------
variable "jenkins_instance_type" {
  type        = string
  description = "EC2 instance type for Jenkins"
  default     = "t3.medium"
}

variable "jenkins_key_name" {
  type        = string
  description = "Name of the EC2 key pair for SSH access to Jenkins"
}

variable "jenkins_ansible_tag" {
  type        = string
  description = "Tag value for Ansible dynamic inventory (key = service)"
  default     = "jenkins"
}

variable "jenkins_associate_public_ip" {
  type        = bool
  description = "Associate a public IP address with Jenkins EC2"
  default     = true
}

variable "ami_owners" {
  type        = list(string)
  description = "AMI owners for data.aws_ami (e.g. amazon)"
  default     = ["amazon"]
}

variable "ami_name_filter" {
  type        = string
  description = "AMI name filter for Amazon Linux 2"
  default     = "amzn2-ami-hvm-*-x86_64-gp2"
}

variable "sg_ingress_protocol" {
  type        = string
  description = "Security group ingress protocol (tcp/udp/icmp)"
  default     = "tcp"
}

# -----------------------------------------------------------------------------
# ECR
# -----------------------------------------------------------------------------
variable "ecr_repository_name" {
  type        = string
  description = "ECR repository name for the application image (Jenkins pushes here)"
  default     = "ivolve-app"
}

# -----------------------------------------------------------------------------
# EKS
# -----------------------------------------------------------------------------
variable "eks_cluster_name" {
  type        = string
  description = "EKS cluster name"
  default     = "ivolve-eks"
}

variable "eks_cluster_version" {
  type        = string
  description = "Kubernetes version for EKS (1.29+ required if module enables EKS Auto Mode)"
  default     = "1.30"
}

# -----------------------------------------------------------------------------
# SNS / Alerts
# -----------------------------------------------------------------------------
variable "sns_alert_topic_name" {
  type        = string
  description = "SNS topic name for alerts"
  default     = "jenkins-alerts-topic"
}

variable "sns_alert_email" {
  type        = string
  description = "Email address for SNS alert subscription"
}

variable "sns_subscription_protocol" {
  type        = string
  description = "SNS subscription protocol (e.g. email, sms)"
  default     = "email"
}

# -----------------------------------------------------------------------------
# CloudWatch Alarm
# -----------------------------------------------------------------------------
variable "cloudwatch_alarm_name" {
  type        = string
  description = "CloudWatch alarm name for Jenkins EC2 CPU"
  default     = "jenkins-ec2-high-cpu"
}

variable "cloudwatch_alarm_threshold" {
  type        = number
  description = "CPU threshold percentage to trigger alarm"
  default     = 70
}

variable "cloudwatch_alarm_evaluation_periods" {
  type        = number
  description = "Number of periods to evaluate before alarming"
  default     = 2
}

variable "cloudwatch_alarm_period" {
  type        = number
  description = "Period in seconds for metric evaluation"
  default     = 300
}

variable "cloudwatch_alarm_description" {
  type        = string
  description = "Description for the CloudWatch alarm"
  default     = "CPU > 70% for Jenkins EC2"
}

variable "cloudwatch_alarm_comparison_operator" {
  type        = string
  description = "CloudWatch alarm comparison operator"
  default     = "GreaterThanThreshold"
}

variable "cloudwatch_alarm_metric_name" {
  type        = string
  description = "CloudWatch metric name"
  default     = "CPUUtilization"
}

variable "cloudwatch_alarm_namespace" {
  type        = string
  description = "CloudWatch metric namespace"
  default     = "AWS/EC2"
}

variable "cloudwatch_alarm_statistic" {
  type        = string
  description = "CloudWatch alarm statistic"
  default     = "Average"
}
