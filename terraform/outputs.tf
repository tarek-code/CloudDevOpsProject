output "jenkins_public_ip" {
  value = module["jenkins-ec2"].public_ip
}

output "eks_cluster_name" {
  value = module.eks.cluster_name
}
