output "jenkins_public_ip" {
  value = module.jenkins_ec2.public_ip
}

output "eks_cluster_name" {
  value = module.eks.cluster_name
}

output "vpc_id" {
  value       = module.vpc.vpc_id
  description = "VPC ID (use with scripts/cleanup-vpc-dependencies.sh before destroy if needed)"
}
