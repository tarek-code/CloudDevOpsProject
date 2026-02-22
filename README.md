# 📘 CloudDevOpsProject — Complete Technical Book

---

## 📌 FRONT MATTER

### 🏷️ Badges

> **📌 Note:** Wire these to your real services (Jenkins job, Terraform Cloud workspace, etc.) when you deploy.

Build
Terraform
Ansible
Docker
Kubernetes
AWS EKS
ArgoCD
License

---

### 📸 Screenshots

> **📌 Note:** Filenames below are examples. Rename them to match the actual files you added (for example under a `Screenshots/` folder) so the images render correctly on GitHub.

| Jenkins Pipeline View | ALB & Target Group | Final App Result |
| --------------------- | ------------------ | ---------------- |
| ![Jenkins Pipeline](Screenshots/jenkins-pipline-created-after-ansible-finished.png) | ![ALB & Target Group](Screenshots/aws-alb-info.png) | ![Final Result](Screenshots/final-result-from-alb.png) |

- **Left**: Jenkins multi‑stage pipeline (build → scan → push → update manifests → post actions).  
- **Middle**: Argo CD showing the application synced and healthy in the EKS cluster.  
- **Right**: The Python/Flask app successfully served through the AWS ALB and Kubernetes Ingress.

---

### 📑 Table of Contents

- [📘 CloudDevOpsProject — Complete Technical Book](#-clouddevopsproject--complete-technical-book)
  - [📌 FRONT MATTER](#-front-matter)
    - [🏷️ Badges](#️-badges)
    - [📸 Screenshots](#-screenshots)
    - [📑 Table of Contents](#-table-of-contents)
  - [CHAPTER 0 — Introduction](#chapter-0--introduction)
    - [0.1 — What is This Project?](#01--what-is-this-project)
    - [0.2 — Technology Stack](#02--technology-stack)
    - [0.3 — Pipeline Overview (High Level)](#03--pipeline-overview-high-level)
  - [CHAPTER 1 — Infrastructure Provisioning with Terraform](#chapter-1--infrastructure-provisioning-with-terraform)
    - [Lesson 1.1 — `terraform/providers.tf](#lesson-11--file-terraformproviderstf)`
    - [Lesson 1.2 — `terraform/variables.tf](#lesson-12--file-terraformvariablestf)`
    - [Lesson 1.3 — `terraform/terraform.tfvars` / `.example](#lesson-13--file-terraformterraformtfvars--terraformterraformtfvarsexample)`
    - [Lesson 1.4 — `terraform/backend.tf](#lesson-14--file-terraformbackendtf)`
    - [Lesson 1.5 — `terraform/main.tf](#lesson-15--file-terraformmaintf)`
    - [Lesson 1.6 — `terraform/outputs.tf](#lesson-16--file-terraformoutputstf)`
    - [Lesson 1.7 — `terraform/trust-policy.json` & `terraform/alb-controller-iam-policy.json](#lesson-17--file-terraformtrust-policyjson--terraformalb-controller-iam-policyjson)`
    - [Lesson 1.8 — `terraform/scripts/cleanup-vpc-dependencies.sh](#lesson-18--file-terraformscriptscleanup-vpc-dependenciessh)`
  - [CHAPTER 2 — Configuration Management with Ansible](#chapter-2--configuration-management-with-ansible)
    - [Sub-Chapter 2.1 — Ansible Foundations](#sub-chapter-21--ansible-foundations)
      - [Lesson 2.1.1 — `ansible/inventory/ec2.aws_ec2.yaml](#lesson-211--file-ansibleinventoryec2awsec2yaml)`
      - [Lesson 2.1.2 — `ansible/main.yaml](#lesson-212--file-ansiblemainyaml)`
      - [Lesson 2.1.3 — `ansible/requirements.yml](#lesson-213--file-ansiblerequirementsyml)`
      - [Lesson 2.1.4 — `ansible/group_vars/all/vault.yml.example` & `service_jenkins.yml](#lesson-214--file-ansiblegroup_varsallvaultymlexample--service_jenkinsyml)`
    - [Sub-Chapter 2.2 — Role: Jenkins](#sub-chapter-22--role-jenkins)
      - [Lesson 2.2.1 — `roles/Jenkins/defaults/main.yml](#lesson-221--file-ansiblerolesjenkinsdefaultsmainyml)`
      - [Lesson 2.2.2 — `roles/Jenkins/handlers/main.yaml](#lesson-222--file-ansiblerolesjenkinshandlersmainyaml)`
      - [Lesson 2.2.3 — `roles/Jenkins/tasks/main.yaml](#lesson-223--file-ansiblerolesjenkinstasksmainyaml)`
      - [Lesson 2.2.4 — `roles/Jenkins/tasks/jenkins-shared-library.yaml](#lesson-224--file-ansiblerolesjenkinstasksjenkins-shared-libraryyaml)`
      - [Lesson 2.2.5 — `roles/Jenkins/templates/global-shared-library.groovy.j2](#lesson-225--file-ansiblerolesjenkinstemplatesglobal-shared-librarygroovyj2)`
      - [Lesson 2.2.6 — `roles/Jenkins/templates/seed-pipeline-job.groovy.j2](#lesson-226--file-ansiblerolesjenkinstemplatesseed-pipeline-jobgroovyj2)`
    - [Sub-Chapter 2.3 — Role: alb-iam](#sub-chapter-23--role-alb-iam)
      - [Lesson 2.3.1 — `roles/alb-iam/files/alb-policy.json](#lesson-231--file-ansiblerolesalb-iamfilesalb-policyjson)`
      - [Lesson 2.3.2 — `roles/alb-iam/tasks/main.yaml](#lesson-232--file-ansiblerolesalb-iamtasksmainyaml)`
      - [Lesson 2.3.3 — `roles/alb-iam/templates/serviceaccount.yaml.j2](#lesson-233--file-ansiblerolesalb-iamtemplatesserviceaccountyamlj2)`
    - [Sub-Chapter 2.4 — Role: helm-install](#sub-chapter-24--role-helm-install)
      - [Lesson 2.4.1 — `roles/helm-install/files/alb-controller-fargate-values.yaml](#lesson-241--file-ansibleroleshelm-installfilesalb-controller-fargate-valuesyaml)`
      - [Lesson 2.4.2 — `roles/helm-install/files/argocd-fargate-values.yaml](#lesson-242--file-ansibleroleshelm-installfilesargocd-fargate-valuesyaml)`
      - [Lesson 2.4.3 — `roles/helm-install/tasks/main.yaml](#lesson-243--file-ansibleroleshelm-installtasksmainyaml)`
  - [CHAPTER 3 — The Application](#chapter-3--the-application)
  - [CHAPTER 4 — Containerization with Docker](#chapter-4--containerization-with-docker)
  - [CHAPTER 5 — CI/CD with Jenkins](#chapter-5--cicd-with-jenkins)
  - [CHAPTER 6 — GitOps with ArgoCD](#chapter-6--gitops-with-argocd)
  - [CHAPTER 7 — Kubernetes Manifests](#chapter-7--kubernetes-manifests)
  - [CHAPTER 8 — Architecture Deep Dive](#chapter-8--architecture-deep-dive)
  - [CHAPTER 9 — Problems & Solutions](#chapter-9--problems--solutions)
  - [CHAPTER 10 — Appendix: Original Documentation](#chapter-10--appendix-original-documentation)
  - [CHAPTER 11 — About the Author & Acknowledgments](#chapter-11--about-the-author--acknowledgments)

> **📌 Note:** Due to the size of the project, some long files are shown as excerpts with `...` to indicate omitted lines. Explanations still cover the full behavior.

---

## CHAPTER 0 — Introduction

### 0.1 — What is This Project?

CloudDevOpsProject is a **complete, cloud‑native CI/CD and GitOps pipeline** that takes a simple Python web app all the way from **source code on GitHub** to **a publicly accessible URL on AWS**, running on **EKS Fargate** behind an **Application Load Balancer (ALB)**.

Concretely, this project:

- Provisions AWS infrastructure (VPC, subnets, IGW, NACLs, EKS, EC2, ECR, IAM, SNS/CloudWatch) using **Terraform**.
- Configures a Jenkins EC2 instance with **Ansible** (Jenkins, Docker, Trivy, kubectl, AWS CLI v2, Helm, Argo CD, ALB controller).
- Uses **Jenkins** + a **Jenkins Shared Library** to:
  - Build the Docker image for the Python app.
  - Scan it with **Trivy**.
  - Push it to **ECR**.
  - Update Kubernetes manifests.
  - Push those manifests back to **GitHub**.
- Uses **Argo CD** to continuously sync the `k8s/` directory from GitHub into the **EKS** cluster.
- Exposes the app via a Kubernetes **Ingress** managed by the **AWS Load Balancer Controller**, which in turn creates an **internet‑facing ALB** in public subnets.

You will learn:

- How to design AWS networking (VPC, subnets, NACLs, SGs) for an EKS Fargate cluster with ALB.
- How to codify infrastructure with Terraform and safely manage state using Terraform Cloud.
- How to use Ansible roles to bootstrap and configure a CI/CD host and cluster add‑ons.
- How to model a CI/CD pipeline in Jenkins with a Shared Library.
- How GitOps with Argo CD keeps Kubernetes in sync with Git.
- How to debug real production‑style issues (ALB timeouts, NACL mistakes, IAM/IRSA, VPC destroy).

This README is written so that **a beginner** can follow step‑by‑step, but also detailed enough that an **experienced engineer** will find patterns and best practices to reuse.

---

### 0.2 — Technology Stack


| Technology                       | What It Is                                                           | Why Used in This Project                                                                                                                | Where It Fits                                                               |
| -------------------------------- | -------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| **Terraform**                    | IaC tool to declaratively manage infrastructure as code.             | To create VPC, subnets, route tables, NACLs, IGW, Jenkins EC2, EKS (Fargate), ECR, IAM roles, SNS, CloudWatch.                          | Run from `terraform/` to provision all AWS resources before any app deploy. |
| **Ansible**                      | Agentless configuration management & orchestration via SSH and YAML. | To configure Jenkins EC2 (packages, Jenkins, Docker, Trivy, kubectl, AWS CLI, Helm, Argo CD, ALB controller) without installing agents. | Run from `ansible/` once Terraform has created Jenkins EC2.                 |
| **Jenkins**                      | CI/CD server that executes pipelines.                                | To build, scan, push Docker images, and update K8s manifests using a clean, reusable Shared Library.                                    | `Jenkinsfile` + `Shared-Library/vars/*.groovy`.                             |
| **Docker**                       | Container runtime and image format.                                  | To package the Python app into a reproducible artifact, decoupled from host OS.                                                         | `docker/Dockerfile` used in Jenkins build stage.                            |
| **Trivy**                        | Container vulnerability scanner.                                     | To scan images for CVEs before pushing to ECR, adding security to the pipeline.                                                         | Called from `scanImage.groovy` in the Shared Library.                       |
| **ECR**                          | AWS Elastic Container Registry.                                      | To host container images close to EKS with IAM‑based auth.                                                                              | Terraform creates ECR repo; Jenkins pushes images there.                    |
| **EKS (Fargate)**                | AWS managed Kubernetes with serverless pods.                         | To run the app and controllers without managing worker nodes. Fargate simplifies node ops and scales as needed.                         | Terraform `module "eks"`; pods scheduled in private subnets.                |
| **Kubernetes**                   | Container orchestration platform.                                    | To define the app as code (`Deployment`, `Service`, `Ingress`) and manage scaling and health.                                           | Manifests in `k8s/`.                                                        |
| **Argo CD**                      | GitOps controller for Kubernetes.                                    | To sync Kubernetes manifests from Git so that cluster state **is Git state**.                                                           | `argocd/application.yaml` tells Argo which repo/path to sync.               |
| **Helm**                         | Package manager for Kubernetes.                                      | To install Argo CD and the AWS Load Balancer Controller with Fargate tolerations and config.                                            | Used in Ansible `helm-install` role.                                        |
| **AWS Load Balancer Controller** | K8s controller that translates Ingress/Service into AWS ALBs/NLBs.   | To create/manage ALBs in front of the app and keep them in sync with K8s objects.                                                       | Installed via Helm; IAM/IRSA defined in Terraform & Ansible.                |


> **📌 Tip:** When learning, read this README in order. Terraform → Ansible → Jenkins → Argo CD → Kubernetes will give you a clear mental model.

---

### 0.3 — Pipeline Overview (High Level)

In plain English, this is what happens from `git push` to “app live in browser”:

1. **Developer pushes code to GitHub**
  - Codebase includes:
    - `app-project/` (Python Flask app)
    - `docker/Dockerfile`
    - `k8s/*.yaml` (namespace, deployment, service, ingress)
    - `terraform/` (infrastructure)
    - `ansible/` (configuration)
    - `Jenkinsfile` and Shared Library
    - `argocd/application.yaml`
2. **Jenkins job (seeded by init Groovy) runs the pipeline**
  - Jenkins uses `Jenkinsfile` and `@Library('ivolve-shared-library@main')`.
3. **Checkout**
  - Jenkins checks out the repo from GitHub (using configured GitHub credentials).
4. **BuildImage**
  - Shared library function `buildImage(imageName, workDir, dockerfile)`:
    - Runs `docker build` with `docker/Dockerfile`.
    - Tags image as `ECR_REPOSITORY:BUILD_NUMBER`.
5. **ScanImage**
  - Shared library `scanImage(imageName)`:
    - Ensures Trivy is installed (pinned version).
    - Scans the built image for vulnerabilities.
6. **PushImage**
  - Shared library `pushImageECR(imageName, region)`:
    - Uses Jenkins EC2 IAM role to login to ECR (no static creds).
    - Pushes the image.
7. **RemoveImageLocally**
  - Shared library `removeImageLocally(imageName)`:
    - Prunes local Docker images to keep Jenkins disk clean.
8. **UpdateManifests**
  - Shared library `updateManifests(imageUrl, manifestsDir)`:
    - Uses `sed` to update `image:` line in `k8s/deployment.yaml` with the new ECR image + tag.
9. **PushManifests**
  - Shared library `pushManifests(commitMsg, manifestsDir, branch, credentialId, repoUrl)`:
    - Commits and pushes the updated `k8s/` directory back to GitHub.
10. **Argo CD sees the Git change**
  - `argocd/application.yaml` is configured with:
    - `repoURL: https://github.com/.../CloudDevOpsProject.git`
    - `path: k8s`
    - `automated` sync (prune + selfHeal).
    - Argo CD reconciles cluster state → applies updated Deployment image.
11. **Kubernetes rolls out new pods**
  - EKS (Fargate) spins up new pods with the **new image tag**.
    - When healthy, old pods are terminated.
12. **AWS Load Balancer Controller ensures ALB is updated**
  - ALB references pods as IP targets (target‑type: ip).
    - Health checks confirm pods are healthy.
    - ALB exposes HTTP 80 to the internet.
13. **User visits ALB DNS**
  - Browser → ALB DNS → Ingress → Service → Pods.
    - Flask app responds with `index.html`.

---

## CHAPTER 1 — Infrastructure Provisioning with Terraform

> **Structure:** Each Terraform file = **Lesson**. For each, we show the file, then explain in detail.

---

### Lesson 1.1 — File: `terraform/providers.tf`

**📄 File:** `terraform/providers.tf`

```hcl
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.32.1"
    }
  }
}

provider "aws" {
  region              = var.aws_region
  profile             = var.aws_profile
  allowed_account_ids = [var.aws_account_id]
  access_key          = var.AWS_ACCESS_KEY_ID
  secret_key          = var.AWS_SECRET_ACCESS_KEY
}
```

**Purpose (2–3 sentences)**  
This file tells Terraform **which provider plugin** to use and **how to talk to AWS**. It centralizes provider configuration (region, account, credentials) so the rest of the Terraform code can focus on resources.

#### Detailed explanation

1. `terraform { required_providers { ... } }`
  - Configures the Terraform CLI itself.
  - `required_providers` is a map of provider names to configuration like source & version.
  - Here, only the `aws` provider is required.
2. `aws = { source = "hashicorp/aws"; version = "6.32.1" }`
  - `source` tells Terraform to download the provider from the official HashiCorp registry.
  - `version` pins the provider — ensures consistent behavior over time.
  - If you removed or loosened this, future `terraform init` could pull a new version that changes defaults (risking breakage).
3. `provider "aws" { ... }`
  - Declares and configures the **default** AWS provider instance.
  - All `aws_`* resources in the configuration use this by default.
4. `region = var.aws_region`
  - Takes value from `variable "aws_region"` (defined in `variables.tf`).
  - Allows easy switching between regions by editing `.tfvars`.
5. `profile = var.aws_profile`
  - Optionally uses a named AWS CLI profile (e.g., `"default"`).
  - In Terraform Cloud, this is often left `null`.
6. `allowed_account_ids = [var.aws_account_id]`
  - Extra safety: ensures the credentials used actually belong to the expected AWS account.
  - If credentials point to a different account, Terraform fails fast.
7. `access_key` & `secret_key`
  - Wired to `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` variables.
  - Marked `sensitive` in `variables.tf`.
  - In practice: set via Terraform Cloud / environment variables, **never** hard‑code them.

> **📌 Note:** In professional setups, you’d often omit `access_key` and `secret_key` and rely on the environment or role federation. This repo is explicit to make behavior predictable for learners.

---

### Lesson 1.2 — File: `terraform/variables.tf`

**📄 File:** `terraform/variables.tf` (excerpt; 300+ lines)

```hcl
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
  default     = "183631347882"
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

...

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

...

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

...

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

...
```

**Purpose (2–3 sentences)**  
This file declares **all Terraform input variables** used throughout the configuration. Variables make the infrastructure definition reusable across environments by separating **what** you provision (code) from **with what values** (tfvars).

#### What are variables in Terraform?

- **Variables** are configuration inputs that you can override from:
  - `terraform.tfvars` / `.auto.tfvars`
  - CLI flags (`-var`)
  - Environment variables (if wired).
- They let you avoid hard‑coding values like region, account, CIDRs, or key pair names.

#### Every variable group (high level)

1. **AWS / Provider variables**
  - `aws_region`, `aws_profile`, `aws_account_id`:
    - Determine where Terraform deploys and which AWS account is allowed.
  - `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`:
    - Credentials (sensitive) — best set via Terraform Cloud.
2. **Project / Naming**
  - `project_name`:
    - Prefix/name tag for resources → easy filtering in AWS console (`ivolve-`*).
3. **VPC variables**
  - `vpc_cidr`, `vpc_azs`:
    - Overall network address space and AZ distribution.
  - `vpc_public_subnet_cidrs`, `vpc_private_subnet_cidrs`:
    - Subnet ranges for public (ALB, Jenkins) and private (Fargate pods) networks.
  - NAT, VPN, DNS, IGW toggles:
    - Provide flexibility for different networking topologies.
  - `allowed_cidr`, `ssh_port`, `jenkins_port`, `https_port`:
    - Define allowed inbound ports and CIDRs for NACLs/SGs.
  - `egress_`*:
    - “Allow all” egress from instances by default.
4. **Jenkins EC2 variables**
  - Instance type, key name, whether to attach public IP.
  - `jenkins_ansible_tag` used by dynamic inventory to select hosts.
5. **ECR / EKS variables**
  - `ecr_repository_name`:
    - Must match Jenkinsfile’s ECR image root.
  - `eks_cluster_name` & `eks_cluster_version`:
    - Must align with Ansible (`cluster_name`) and Argo CD’s Application (`destination.namespace` & `source` config).
6. **SNS / CloudWatch**
  - Email topic and CloudWatch alarm parameters for Jenkins EC2.

> **📌 Tip:** When reading `main.tf`, cross‑reference variable names with this file to understand where values come from.

---

### Lesson 1.3 — File: `terraform/terraform.tfvars` / `terraform/terraform.tfvars.example`

**📄 File:** `terraform/terraform.tfvars.example`

```hcl
# Copy to terraform.tfvars and set values. Do not commit terraform.tfvars.
# Sensitive: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY (use Terraform Cloud or env).

aws_region     = "us-east-1"
# aws_profile  = "default"
aws_account_id = "YOUR_AWS_ACCOUNT_ID"

project_name = "ivolve"

vpc_cidr                    = "10.0.0.0/16"
vpc_azs                     = ["us-east-1a", "us-east-1b"]
vpc_public_subnet_cidrs     = ["10.0.1.0/24", "10.0.2.0/24"]
vpc_private_subnet_cidrs    = ["10.0.11.0/24", "10.0.12.0/24"]
vpc_enable_nat_gateway      = true
vpc_single_nat_gateway      = true
vpc_enable_vpn_gateway      = false
vpc_enable_dns_hostnames    = true
vpc_enable_internet_gateway = true
nacl_tcp_protocol           = "6"

allowed_cidr      = "0.0.0.0/0"
ssh_port          = 22
jenkins_port      = 8080
https_port        = 443
egress_from_port  = 0
egress_to_port    = 0
egress_protocol   = "-1"
egress_cidr       = "0.0.0.0/0"

jenkins_instance_type       = "t3.medium"
jenkins_key_name            = "jenkins_key"
jenkins_ansible_tag         = "jenkins"
jenkins_associate_public_ip = true
ami_owners                  = ["amazon"]
ami_name_filter             = "amzn2-ami-hvm-*-x86_64-gp2"
sg_ingress_protocol         = "tcp"

ecr_repository_name = "ivolve-app"

eks_cluster_name    = "ivolve-eks"
eks_cluster_version = "1.29"

sns_alert_topic_name      = "jenkins-alerts-topic"
sns_alert_email           = "your-email@example.com"
sns_subscription_protocol = "email"

cloudwatch_alarm_name               = "jenkins-ec2-high-cpu"
cloudwatch_alarm_threshold          = 70
cloudwatch_alarm_evaluation_periods = 2
cloudwatch_alarm_period             = 300
cloudwatch_alarm_description        = "CPU > 70% for Jenkins EC2"
cloudwatch_alarm_comparison_operator = "GreaterThanThreshold"
cloudwatch_alarm_metric_name        = "CPUUtilization"
cloudwatch_alarm_namespace          = "AWS/EC2"
cloudwatch_alarm_statistic          = "Average"
```

**📄 File:** `terraform/terraform.tfvars`

```hcl
aws_region = "us-east-1"
aws_account_id = "183631347882"

project_name = "ivolve"

vpc_cidr                    = "10.0.0.0/16"
vpc_azs                     = ["us-east-1a", "us-east-1b"]
vpc_public_subnet_cidrs     = ["10.0.1.0/24", "10.0.2.0/24"]
vpc_private_subnet_cidrs    = ["10.0.11.0/24", "10.0.12.0/24"]
vpc_enable_nat_gateway      = true
vpc_single_nat_gateway      = true
vpc_enable_vpn_gateway      = false
vpc_enable_dns_hostnames    = true
vpc_enable_internet_gateway = true
nacl_tcp_protocol           = "6"

allowed_cidr     = "0.0.0.0/0"
ssh_port         = 22
jenkins_port     = 8080
https_port       = 443
egress_from_port = 0
egress_to_port   = 0
egress_protocol  = "-1"
egress_cidr      = "0.0.0.0/0"

jenkins_instance_type       = "t3.medium"
jenkins_key_name            = "Jenkins_key"
jenkins_ansible_tag         = "jenkins"
jenkins_associate_public_ip = true
ami_owners                  = ["amazon"]
ami_name_filter             = "amzn2-ami-hvm-*-x86_64-gp2"
sg_ingress_protocol         = "tcp"

eks_cluster_name    = "ivolve-eks"
eks_cluster_version = "1.30"

sns_alert_topic_name      = "jenkins-alerts-topic"
sns_alert_email           = "pootyoop14@gmail.com"
sns_subscription_protocol = "email"

cloudwatch_alarm_name                = "jenkins-ec2-high-cpu"
cloudwatch_alarm_threshold           = 70
cloudwatch_alarm_evaluation_periods  = 2
cloudwatch_alarm_period              = 300
cloudwatch_alarm_description         = "CPU > 70% for Jenkins EC2"
cloudwatch_alarm_comparison_operator = "GreaterThanThreshold"
cloudwatch_alarm_metric_name         = "CPUUtilization"
cloudwatch_alarm_namespace           = "AWS/EC2"
cloudwatch_alarm_statistic           = "Average"
```

**Purpose**  

- `.example` is a **template** file that you copy to `terraform.tfvars`.
- `terraform.tfvars` holds your **actual environment values** and should usually **not be committed** if it contains secrets or account‑specific details.

Key points:

- Every variable in `.tfvars` corresponds to one in `variables.tf`.
- This is where you set:
  - The actual account ID.
  - The Jenkins EC2 key pair name.
  - Subnet CIDRs.
  - Alert email address.

> **📌 Note:** The pattern `*.tfvars.example` is common: it documents expected inputs without leaking real secrets into Git.

---

### Lesson 1.4 — File: `terraform/backend.tf`

**📄 File:** `terraform/backend.tf`

```hcl
terraform {
  cloud {

    organization = "iVolve-project"

    workspaces {
      name = "iVolve-dev"
    }
  }
}
```

**Purpose**

- Configures Terraform to use **Terraform Cloud** as the backend for state.
- Uses organization `iVolve-project` and workspace name `iVolve-dev`.

Why remote state matters:

- Prevents local state files from being accidentally deleted or corrupted.
- Enables state locking → avoids two people applying at the same time.
- Provides centralized audit log & version history.

If you removed this:

- Terraform would default to local `terraform.tfstate`.
- You’d need to manage backups, collaboration and locking manually.

---

### Lesson 1.5 — File: `terraform/main.tf`

> **📌 Note:** This file is large; we show key sections and explain all core resources.

**📄 File:** `terraform/main.tf` (VPC section)

```hcl
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
```

**Purpose**

- Creates the **VPC** and all associated networking resources using the mature `terraform-aws-modules/vpc/aws` module.
- Customizes:
  - CIDR, subnets, NAT.
  - Public NACL to explicitly allow HTTP 80 for ALB (critical fix from troubleshooting).
  - Proper Kubernetes subnet tags for ALB controller and EKS.

Key details:

- `public_dedicated_network_acl = true` — ensures public subnets use a dedicated NACL we fully control.
- `public_inbound_acl_rules`:
  - 100 → SSH (22).
  - 110 → Jenkins UI (8080).
  - 120 → HTTPS (443).
  - 125 → **HTTP 80 from 0.0.0.0/0** for ALB.
  - 130 → Return traffic (1024–65535) from anywhere.
- `public_subnet_tags`:
  - `kubernetes.io/role/elb=1` — ALB controller uses these for internet‑facing ALBs.
  - `kubernetes.io/cluster/<clusterName>=shared` — standard Kubernetes/EKS tag.
- `private_subnet_tags`:
  - `kubernetes.io/role/internal-elb=1` — for internal load balancers if needed.

> **📌 Lesson learned:** Initially, port 80 was not allowed in NACL → ALB timed out. Adding rule 125 fixed it. This is codified here to prevent regression.

#### 1.x — Terraform Apply (Infrastructure Provisioned)

1. From the `terraform/` directory, run `terraform init` and then `terraform apply`.  
2. Review the plan carefully, then type `yes` to create the AWS resources.  
3. When the apply finishes, note the outputs (EKS name, VPC ID, Jenkins IP, etc.) for later steps.

![Terraform Apply](Screenshots/hashocorp-workspace-runs.png)

> **📌 Tip:** Commit your `.tf` files, but never commit real `terraform.tfvars` with secrets or personal account IDs.

**📄 File:** `terraform/main.tf` (Security group)

```hcl
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
```

- Allows Jenkins UI and SSH from `allowed_cidr` (0.0.0.0/0 by default; you may want to lock to your IP in production).
- Allows all outbound.

**📄 File:** `terraform/main.tf` (Jenkins IAM role)

```hcl
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
```

- Grants Jenkins EC2 IAM role permissions for:
  - ECR login/push.
  - EKS DescribeCluster (for kubeconfig).
  - Read‑only ELB/EC2 Describe* for debugging ALB/subnet issues from the host.

**📄 File:** `terraform/main.tf` (ECR & Jenkins EC2)

```hcl
resource "aws_ecr_repository" "app" {
  name                 = var.ecr_repository_name
  image_tag_mutability = "MUTABLE"
  force_delete         = true # Allow destroy even when repository has images
}

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
```

- ECR:
  - `force_delete` ensures you can tear down infra even if images remain.
- Jenkins EC2:
  - Uses public subnet 0.
  - Tagged `service=jenkins` for dynamic inventory.

**📄 File:** `terraform/main.tf` (EKS + Fargate)

```hcl
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
```

- Schedules everything on Fargate (no worker nodes).
- Grants Jenkins role cluster‑admin via access entries.
- Allows Jenkins SG to talk to EKS API on 443.

**📄 File:** `terraform/main.tf` (CoreDNS + IRSA + ALB controller + SNS + CloudWatch)  
*(See earlier explanation; due to length we won’t repeat here.)*

---

### Lesson 1.6 — File: `terraform/outputs.tf`

**📄 File:** `terraform/outputs.tf`

```hcl
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
```

*(See explanation earlier in this conversation.)*

---

### Lesson 1.7 — File: `terraform/trust-policy.json` & `terraform/alb-controller-iam-policy.json`

**📄 File:** `terraform/trust-policy.json`

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::183631347882:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/BB95ADDE24F224536BB7E5300F668E35"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.eks.us-east-1.amazonaws.com/id/BB95ADDE24F224536BB7E5300F668E35:aud": "sts.amazonaws.com",
          "oidc.eks.us-east-1.amazonaws.com/id/BB95ADDE24F224536BB7E5300F668E35:sub": "system:serviceaccount:kube-system:aws-load-balancer-controller"
        }
      }
    }
  ]
}
```

**Purpose**

- This is a **trust policy** for an IAM role used by the AWS Load Balancer Controller via IRSA.
- It allows only:
  - Tokens issued by the EKS OIDC provider in account `183631347882`.
  - For the ServiceAccount `system:serviceaccount:kube-system:aws-load-balancer-controller`.
- It uses `sts:AssumeRoleWithWebIdentity`, which is how IRSA works.

**Key points:**

- `Principal.Federated` — the ARN of the EKS OIDC provider.
- `Condition.StringEquals`:
  - Forces `aud` to be `sts.amazonaws.com`.
  - Restricts `sub` to exactly that ServiceAccount.

**📄 File:** `terraform/alb-controller-iam-policy.json`

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["iam:CreateServiceLinkedRole"],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "iam:AWSServiceName": "elasticloadbalancing.amazonaws.com"
        }
      }
    },
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeAccountAttributes",
        "ec2:DescribeAddresses",
        "ec2:DescribeAvailabilityZones",
        "ec2:DescribeInternetGateways",
        "ec2:DescribeVpcs",
        "ec2:DescribeVpcPeeringConnections",
        "ec2:DescribeSubnets",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeInstances",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeTags",
        "ec2:GetCoipPoolUsage",
        "ec2:DescribeCoipPools",
        "ec2:GetSecurityGroupsForVpc",
        "ec2:DescribeIpamPools",
        "ec2:DescribeRouteTables",
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeLoadBalancerAttributes",
        "elasticloadbalancing:DescribeListeners",
        "elasticloadbalancing:DescribeListenerCertificates",
        "elasticloadbalancing:DescribeSSLPolicies",
        "elasticloadbalancing:DescribeRules",
        "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeTargetGroupAttributes",
        "elasticloadbalancing:DescribeTargetHealth",
        "elasticloadbalancing:DescribeTags",
        "elasticloadbalancing:DescribeTrustStores",
        "elasticloadbalancing:DescribeListenerAttributes",
        "elasticloadbalancing:DescribeCapacityReservation"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "cognito-idp:DescribeUserPoolClient",
        "acm:ListCertificates",
        "acm:DescribeCertificate",
        "iam:ListServerCertificates",
        "iam:GetServerCertificate",
        "waf-regional:GetWebACL",
        "waf-regional:GetWebACLForResource",
        "waf-regional:AssociateWebACL",
        "waf-regional:DisassociateWebACL",
        "wafv2:GetWebACL",
        "wafv2:GetWebACLForResource",
        "wafv2:AssociateWebACL",
        "wafv2:DisassociateWebACL",
        "shield:GetSubscriptionState",
        "shield:DescribeProtection",
        "shield:CreateProtection",
        "shield:DeleteProtection"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": ["ec2:AuthorizeSecurityGroupIngress", "ec2:RevokeSecurityGroupIngress"],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": ["ec2:CreateSecurityGroup"],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": ["ec2:CreateTags"],
      "Resource": "arn:aws:ec2:*:*:security-group/*",
      "Condition": {
        "StringEquals": { "ec2:CreateAction": "CreateSecurityGroup" },
        "Null": { "aws:RequestTag/elbv2.k8s.aws/cluster": "false" }
      }
    },
    {
      "Effect": "Allow",
      "Action": ["ec2:CreateTags", "ec2:DeleteTags"],
      "Resource": "arn:aws:ec2:*:*:security-group/*",
      "Condition": {
        "Null": {
          "aws:RequestTag/elbv2.k8s.aws/cluster": "true",
          "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
        }
      }
    },
    {
      "Effect": "Allow",
      "Action": ["ec2:AuthorizeSecurityGroupIngress", "ec2:RevokeSecurityGroupIngress", "ec2:DeleteSecurityGroup"],
      "Resource": "*",
      "Condition": {
        "Null": { "aws:ResourceTag/elbv2.k8s.aws/cluster": "false" }
      }
    },
    {
      "Effect": "Allow",
      "Action": ["elasticloadbalancing:CreateLoadBalancer", "elasticloadbalancing:CreateTargetGroup"],
      "Resource": "*",
      "Condition": { "Null": { "aws:RequestTag/elbv2.k8s.aws/cluster": "false" } }
    },
    {
      "Effect": "Allow",
      "Action": [
        "elasticloadbalancing:CreateListener",
        "elasticloadbalancing:DeleteListener",
        "elasticloadbalancing:CreateRule",
        "elasticloadbalancing:DeleteRule"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": ["elasticloadbalancing:AddTags", "elasticloadbalancing:RemoveTags"],
      "Resource": [
        "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
        "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
        "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*"
      ],
      "Condition": {
        "Null": {
          "aws:RequestTag/elbv2.k8s.aws/cluster": "true",
          "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
        }
      }
    },
    {
      "Effect": "Allow",
      "Action": ["elasticloadbalancing:AddTags", "elasticloadbalancing:RemoveTags"],
      "Resource": [
        "arn:aws:elasticloadbalancing:*:*:listener/net/*/*/*",
        "arn:aws:elasticloadbalancing:*:*:listener/app/*/*/*",
        "arn:aws:elasticloadbalancing:*:*:listener-rule/net/*/*/*",
        "arn:aws:elasticloadbalancing:*:*:listener-rule/app/*/*/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "elasticloadbalancing:ModifyLoadBalancerAttributes",
        "elasticloadbalancing:SetIpAddressType",
        "elasticloadbalancing:SetSecurityGroups",
        "elasticloadbalancing:SetSubnets",
        "elasticloadbalancing:DeleteLoadBalancer",
        "elasticloadbalancing:ModifyTargetGroup",
        "elasticloadbalancing:ModifyTargetGroupAttributes",
        "elasticloadbalancing:DeleteTargetGroup",
        "elasticloadbalancing:ModifyListenerAttributes",
        "elasticloadbalancing:ModifyCapacityReservation",
        "elasticloadbalancing:ModifyIpPools"
      ],
      "Resource": "*",
      "Condition": { "Null": { "aws:ResourceTag/elbv2.k8s.aws/cluster": "false" } }
    },
    {
      "Effect": "Allow",
      "Action": ["elasticloadbalancing:AddTags"],
      "Resource": [
        "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
        "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
        "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*"
      ],
      "Condition": {
        "StringEquals": { "elasticloadbalancing:CreateAction": ["CreateTargetGroup", "CreateLoadBalancer"] },
        "Null": { "aws:RequestTag/elbv2.k8s.aws/cluster": "false" }
      }
    },
    {
      "Effect": "Allow",
      "Action": ["elasticloadbalancing:RegisterTargets", "elasticloadbalancing:DeregisterTargets"],
      "Resource": "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "elasticloadbalancing:SetWebAcl",
        "elasticloadbalancing:ModifyListener",
        "elasticloadbalancing:AddListenerCertificates",
        "elasticloadbalancing:RemoveListenerCertificates",
        "elasticloadbalancing:ModifyRule",
        "elasticloadbalancing:SetRulePriorities"
      ],
      "Resource": "*"
    }
  ]
}
```

**Purpose**

- Grants ALB Controller the permissions to:
  - Discover VPC/ELB resources.
  - Create/modify/delete load balancers, listeners, rules, target groups.
  - Manage security groups and tags in a controlled way.
  - Integrate with WAF, Shield, ACM, and Cognito for advanced features.

> **📌 Summary:** `trust-policy.json` says **“who can assume the ALB controller role”** (EKS ServiceAccount), and `alb-controller-iam-policy.json` says **“what that role can do”** (manage ALBs and SGs for Kubernetes Ingress/Service).

---

### Lesson 1.8 — File: `terraform/scripts/cleanup-vpc-dependencies.sh`

*(Already shown and explained above in detail in Lesson 1.8; see [Lesson 1.8](#lesson-18--file-terraformscriptscleanup-vpc-dependenciessh) for the full script and walkthrough.)*

---

## CHAPTER 2 — Configuration Management with Ansible

This chapter explains how Ansible is used to turn the bare Jenkins EC2 instance created by Terraform into a fully configured **CI/CD control plane**, and how it installs cluster add‑ons (Argo CD and AWS Load Balancer Controller) using Helm. It covers:

- Dynamic inventory against AWS EC2.
- The top‑level playbook `ansible/main.yaml`.
- Per‑role configuration for:
  - Jenkins (packages, Jenkins, Docker, kubectl, AWS CLI, Shared Library, seed job).
  - ALB IAM + ServiceAccount for IRSA.
  - Helm‑based installation of Argo CD and ALB controller.

> **📌 Tip:** Start with Sub‑Chapter 2.1 (“Ansible Foundations”) in this README to understand how inventory, playbooks, and roles interact.

---

### Lesson 2.1.1 — File: `ansible/inventory/ec2.aws_ec2.yaml`

**📄 File:** `ansible/inventory/ec2.aws_ec2.yaml`

```yaml
---
plugin: amazon.aws.aws_ec2
regions:
  - us-east-1
filters:
  instance-state-name: running
  tag:service: jenkins
keyed_groups:
  - key: tags.service
    prefix: service
hostnames:
  - public-ip-address
  - private-ip-address
compose:
  ansible_host: public_ip_address
  ansible_user: ec2-user
  ansible_ssh_private_key_file: "~/.ssh/Jenkins_key.pem"
```

**Purpose:** Dynamic inventory discovers Jenkins EC2 instances from AWS by tags. Creates `service_jenkins` group so the playbook targets only Jenkins hosts.

**Line-by-line:**
- `---` — YAML document start.
- `plugin: amazon.aws.aws_ec2` — Use the AWS EC2 inventory plugin to query EC2 API instead of a static host file.
- `regions: [us-east-1]` — Only discover instances in us-east-1; must match where Terraform created Jenkins.
- `filters:` — Narrow results:
  - `instance-state-name: running` — Ignore stopped/terminated instances.
  - `tag:service: jenkins` — Only instances with `service=jenkins`; matches Terraform `jenkins_ansible_tag`.
- `keyed_groups:` — Create groups from tags:
  - `key: tags.service`, `prefix: service` → group `service_jenkins` for `tag:service=jenkins`.
- `hostnames:` — Use public/private IP as host identifier.
- `compose:` — Override connection variables:
  - `ansible_host: public_ip_address` — Connect via public IP (Jenkins is in a public subnet).
  - `ansible_user: ec2-user` — Standard Amazon Linux 2 user.
  - `ansible_ssh_private_key_file` — Path to the `.pem`; must match `jenkins_key_name` in Terraform.

---

### Lesson 2.1.2 — File: `ansible/main.yaml`

**📄 File:** `ansible/main.yaml`

```yaml
---
- name: Bootstrap Python 3.8 on Jenkins hosts
  hosts: service_jenkins
  gather_facts: false
  become: yes
  vars:
    ansible_become_timeout: 120
  tasks:
    - name: Install Python 3.8 and pip (Amazon Linux 2)
      ansible.builtin.raw: |
        amazon-linux-extras enable -y python3.8
        yum install -y python3.8
      args:
        executable: /bin/bash
    - name: Ensure Python 3.8 is available
      ansible.builtin.raw: test -x /usr/bin/python3.8 && /usr/bin/python3.8 -c 'import sys; print(sys.version)'
      ...
- name: Setup required packages, Jenkins, HELM in EKS, ALB IAM Setup
  hosts: service_jenkins
  become: yes
  gather_facts: yes
  vars:
    cluster_name: "ivolve-eks"
    aws_account_id: "183631347882"
    aws_region: "us-east-1"
  roles:
    - role: Jenkins
    - role: alb-iam
    - role: helm-install
```

**Purpose:** Two-play playbook: first bootstraps Python 3.8 so Ansible modules can run; second applies Jenkins, alb-iam, and helm-install roles to configure the CI/CD host and cluster add-ons.

**Line-by-line:**
- `name: Bootstrap Python 3.8` — First play: install Python on targets before using normal Ansible modules.
- `hosts: service_jenkins` — Run only on hosts in `service_jenkins` (from dynamic inventory).
- `gather_facts: false` — Skip fact gathering because Python 3.8 may not exist yet.
- `become: yes` — Run as root (needed for yum).
- `ansible.builtin.raw` — Run raw shell; avoids requiring Python on the target.
- `amazon-linux-extras enable python3.8` — Enable Python 3.8 repo on Amazon Linux 2.
- `yum install -y python3.8` — Install Python so subsequent plays can use modules.
- Second play: `gather_facts: yes` — Now facts can be gathered.
- `vars:` — Must match Terraform: `cluster_name` = EKS name, `aws_account_id`, `aws_region`.
- `roles:` — Jenkins (packages, Jenkins, Shared Library), alb-iam (ServiceAccount), helm-install (Argo CD, ALB Controller).

---

### Lesson 2.1.3 — File: `ansible/requirements.yml`

**📄 File:** `ansible/requirements.yml`

```yaml
---
# Install before running the playbook (dynamic inventory + alb-iam role need these):
#   ansible-galaxy collection install -r ansible/requirements.yml
collections:
  - name: amazon.aws
    version: ">=6.0.0"
```

**Purpose:** Declares Ansible Galaxy collections required by the playbook. The `amazon.aws` collection provides the AWS EC2 inventory plugin and AWS modules.

**Line-by-line:**
- `---` — YAML document start.
- `collections:` — List of collections to install.
- `name: amazon.aws` — The Amazon AWS collection; includes `aws_ec2` inventory plugin and AWS modules.
- `version: ">=6.0.0"` — Minimum version; use `ansible-galaxy collection install -r ansible/requirements.yml` before running the playbook.

---

### Lesson 2.1.4 — File: `ansible/group_vars/all/vault.yml.example` & `ansible/group_vars/service_jenkins.yml`

**📄 File:** `ansible/group_vars/all/vault.yml.example`

```yaml
# DO NOT put real credentials. Copy to vault.yml, edit, then encrypt.
# With vault: ansible-vault encrypt ansible/group_vars/all/vault.yml
# Or pass via -e: -e jenkins_github_username=YOUR_USER -e jenkins_github_token=YOUR_PAT
---
jenkins_github_username: "your-github-username"
jenkins_github_token: "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

**Purpose:** Example template for GitHub credentials. Used by the Jenkins role to create GitHub credentials in Jenkins. Copy to `vault.yml`, add real values, then encrypt with `ansible-vault encrypt`.

**Line-by-line:**
- `jenkins_github_username` — GitHub username or org for the repo.
- `jenkins_github_token` — GitHub Personal Access Token (PAT) with `repo` scope for push/clone.

---

**📄 File:** `ansible/group_vars/service_jenkins.yml`

```yaml
---
ansible_user: ec2-user
ansible_ssh_private_key_file: "~/.ssh/Jenkins_key.pem"
ansible_python_interpreter: /usr/bin/python3.8
ansible_become_timeout: 120
```

**Purpose:** Group variables for hosts in `service_jenkins`. Applied to all Jenkins EC2 instances discovered by dynamic inventory.

**Line-by-line:**
- `ansible_user: ec2-user` — SSH user on Amazon Linux 2.
- `ansible_ssh_private_key_file` — Path to the `.pem`; must match `jenkins_key_name` in Terraform.
- `ansible_python_interpreter: /usr/bin/python3.8` — Use Python 3.8 so Ansible modules work on Amazon Linux 2.
- `ansible_become_timeout: 120` — Longer timeout for `sudo` on slow or high-latency SSH.

---

### Lesson 2.2.1 — File: `ansible/roles/Jenkins/defaults/main.yml`

**📄 File:** `ansible/roles/Jenkins/defaults/main.yml`

```yaml
---
jenkins_shared_library_name: "ivolve-shared-library"
jenkins_shared_library_version: "main"
jenkins_shared_library_repo: "https://github.com/tarek-code/CloudDevOpsProject.git"
jenkins_shared_library_path: "Shared-Library"
jenkins_home: "/var/lib/jenkins"
jenkins_sysconfig: "/etc/sysconfig/jenkins"
jenkins_github_credential_id: "github-credentials"
```

**Purpose:** Default variables for the Jenkins role. Shared Library config and credential ID are used by Groovy init scripts to configure Jenkins on startup.

**Line-by-line:**
- `jenkins_shared_library_name` — Name shown in Jenkins UI; matches `@Library('ivolve-shared-library@main')` in Jenkinsfile.
- `jenkins_shared_library_version` — Branch/tag to use (e.g. `main`).
- `jenkins_shared_library_repo` — Git URL of the repo containing the Shared Library.
- `jenkins_shared_library_path` — Subfolder in repo with `vars/` (e.g. `Shared-Library`).
- `jenkins_home` — Jenkins data directory on Amazon Linux 2.
- `jenkins_sysconfig` — Sysconfig file for Jenkins service.
- `jenkins_github_credential_id` — Jenkins credential ID for GitHub (used by Shared Library and seed job).

---

### Lesson 2.2.2 — File: `ansible/roles/Jenkins/handlers/main.yaml`

**📄 File:** `ansible/roles/Jenkins/handlers/main.yaml`

```yaml
---
- name: Restart Jenkins
  ansible.builtin.service:
    name: jenkins
    state: restarted
```

**Purpose:** Handler that restarts the Jenkins service. Triggered by `notify: Restart Jenkins` when the Jenkins user is added to the docker group, so Jenkins can use Docker.

**Line-by-line:**
- `---` — YAML document start.
- `name: Restart Jenkins` — Handler name; referenced by `notify: Restart Jenkins`.
- `ansible.builtin.service:` — Uses the service module.
- `name: jenkins` — The Jenkins systemd service.
- `state: restarted` — Restart the service. Handlers run once at the end of the play if notified.

---

### Lesson 2.2.3 — File: `ansible/roles/Jenkins/tasks/main.yaml`

**📄 File:** `ansible/roles/Jenkins/tasks/main.yaml` (key tasks)

```yaml
---
- name: Update all packages
  ansible.builtin.shell: yum update -y
  args: { executable: /bin/bash }

- name: Install required packages (Java 21 for Jenkins 2.541 LTS)
  ansible.builtin.shell: |
    yum install -y git docker trivy tar unzip vim nano curl ...
  args: { executable: /bin/bash }

- name: Enable Corretto 17 and install Java 17 for Jenkins LTS
  ansible.builtin.shell: |
    amazon-linux-extras enable corretto17
    yum install -y java-17-amazon-corretto

- name: Start and enable Docker
  ansible.builtin.service: { name: docker, state: started, enabled: true }

- name: Add Jenkins repo
  ansible.builtin.get_url:
    url: https://pkg.jenkins.io/rpm-stable/jenkins.repo
    dest: /etc/yum.repos.d/jenkins.repo

- name: Install Jenkins
  ansible.builtin.shell: yum install -y jenkins

- name: Add Jenkins user to docker group
  ansible.builtin.user: { name: jenkins, groups: docker, append: true }
  notify: Restart Jenkins

- name: Install kubectl (match EKS 1.30)
  ansible.builtin.get_url:
    url: https://s3.us-west-2.amazonaws.com/amazon-eks/1.30.14/.../kubectl
    dest: /usr/local/bin/kubectl

- name: Install AWS CLI v2
  ansible.builtin.shell: | ... curl ... awscli-exe-linux-x86_64.zip ...

- name: Update kubeconfig
  ansible.builtin.shell: aws eks update-kubeconfig --name {{ cluster_name }} --region {{ aws_region }}

- name: Fix kubeconfig exec apiVersion (v1alpha1 → v1beta1)
  ansible.builtin.shell: sed -i 's/...v1alpha1.../v1beta1.../' /root/.kube/config

- name: Copy kubeconfig to ec2-user
  ansible.builtin.shell: cp /root/.kube/config /home/ec2-user/.kube/config

- name: Configure Jenkins Shared Library
  ansible.builtin.include_tasks: jenkins-shared-library.yaml
```

**Purpose:** Main tasks for the Jenkins role. Install packages, Jenkins, Docker, kubectl, AWS CLI v2, configure kubeconfig, and include the Shared Library setup.

**Line-by-line:**
- `yum update -y` — Update all packages; uses shell because dnf Python module may be missing.
- `yum install -y git docker trivy ...` — Tools needed for the pipeline (Docker for builds, Trivy for scans, etc.).
- `amazon-linux-extras enable corretto17` — Java 17 for Jenkins LTS.
- `yum install -y jenkins` — Jenkins from official repo.
- `notify: Restart Jenkins` — Trigger handler so Jenkins restarts after being added to docker group.
- `kubectl` — Downloaded from EKS URL; version must match cluster.
- `aws eks update-kubeconfig` — Creates kubeconfig for the cluster.
- `sed ... v1alpha1 ... v1beta1` — EKS exec plugin v1alpha1 is deprecated; Helm/kubectl need v1beta1.
- `cp ... to ec2-user` — Lets ec2-user use kubectl when SSH’d (not just root).
- `include_tasks: jenkins-shared-library.yaml` — Runs Shared Library and seed job configuration.

---

### Lesson 2.2.4 — File: `ansible/roles/Jenkins/tasks/jenkins-shared-library.yaml`

**📄 File:** `ansible/roles/Jenkins/tasks/jenkins-shared-library.yaml`

```yaml
---
- name: Ensure Jenkins init.groovy.d directory exists
  ansible.builtin.file:
    path: "{{ jenkins_home }}/init.groovy.d"
    state: directory
    owner: jenkins
    group: jenkins
    mode: "0755"

- name: Deploy Groovy init script to configure Shared Library and GitHub credentials
  ansible.builtin.template:
    src: global-shared-library.groovy.j2
    dest: "{{ jenkins_home }}/init.groovy.d/global-shared-library.groovy"

- name: Deploy Groovy init script to create seed pipeline job
  ansible.builtin.template:
    src: seed-pipeline-job.groovy.j2
    dest: "{{ jenkins_home }}/init.groovy.d/seed-pipeline-job.groovy"

- name: Restart Jenkins to load Groovy init script
  ansible.builtin.service:
    name: jenkins
    state: restarted
```

**Purpose:** Deploys Groovy init scripts into `$JENKINS_HOME/init.groovy.d/`. Jenkins runs these at startup to configure the Shared Library, GitHub credentials, and the seed pipeline job.

**Line-by-line:**
- `path: "{{ jenkins_home }}/init.groovy.d"` — Directory where init scripts live; Jenkins runs them on startup.
- `global-shared-library.groovy` — Configures the Shared Library and GitHub credentials.
- `seed-pipeline-job.groovy` — Creates the CloudDevOpsProject pipeline job that uses the Jenkinsfile.
- `state: restarted` — Restart Jenkins so init scripts run and changes take effect.

---

### Lesson 2.2.5 — File: `ansible/roles/Jenkins/templates/global-shared-library.groovy.j2`

**📄 File:** `ansible/roles/Jenkins/templates/global-shared-library.groovy.j2` (excerpt)

```groovy
// 1) GitHub credentials (if provided)
def ghUser = "{{ jenkins_github_username | default('', true) }}"
def ghToken = "{{ jenkins_github_token | default('', true) }}"
if (ghUser && ghToken) {
  def newCreds = new UsernamePasswordCredentialsImpl(GLOBAL, ghCredId, "GitHub credentials", ghUser, ghToken)
  credsStore.addCredentials(domain, newCreds)
}
// 2) Global Pipeline Library
def libConfig = new LibraryConfiguration(libName, new SCMSourceRetriever(new GitSCMSource(libRepo)))
libConfig.defaultVersion = libVersion
libConfig.implicit = false
libPathField.set(libConfig, "{{ jenkins_shared_library_path | default('Shared-Library', true) }}")
globalLibs.setLibraries(libs)
```

**Purpose:** Groovy init script that runs at Jenkins startup. Creates GitHub credentials (if vars are set) and configures the Global Pipeline Library so `@Library('ivolve-shared-library@main')` works.

**Line-by-line:**
- `ghUser`, `ghToken` — Jinja2 vars from vault or `-e`; empty if not provided.
- `UsernamePasswordCredentialsImpl` — Creates Jenkins credentials for GitHub (used by pipeline and seed job).
- `LibraryConfiguration` — Configures the Shared Library from the Git repo.
- `libPath` — Subfolder in repo (e.g. `Shared-Library`); set via reflection because the API does not expose it directly.

---

### Lesson 2.2.6 — File: `ansible/roles/Jenkins/templates/seed-pipeline-job.groovy.j2`

**📄 File:** `ansible/roles/Jenkins/templates/seed-pipeline-job.groovy.j2`

```groovy
def jobName = "{{ jenkins_seed_job_name | default('CloudDevOpsProject-pipeline', true) }}"
def repoUrl = "{{ jenkins_shared_library_repo }}"
def branch = "{{ jenkins_shared_library_version }}"
def credId = "{{ jenkins_github_credential_id }}"
def jenkinsfilePath = "{{ jenkins_seed_job_jenkinsfile | default('Jenkinsfile', true) }}"

def job = j.getItem(jobName)
if (job == null) { job = j.createProject(WorkflowJob, jobName) }

def scm = new GitSCM(
  [new UserRemoteConfig(repoUrl, null, null, credId)],
  [new BranchSpec("*/${branch}")]
)
def flowDef = new CpsScmFlowDefinition(scm, jenkinsfilePath)
job.setDefinition(flowDef)
job.save()
```

**Purpose:** Groovy init script that creates or updates the pipeline job. The job clones the repo, loads the Jenkinsfile, and runs the CI/CD pipeline.

**Line-by-line:**
- `jobName` — Job name in Jenkins (e.g. `CloudDevOpsProject-pipeline`).
- `repoUrl`, `branch` — Git repo and branch (same as Shared Library).
- `credId` — Jenkins credential ID for Git clone.
- `jenkinsfilePath` — Path to Jenkinsfile in repo (e.g. `Jenkinsfile`).
- `CpsScmFlowDefinition` — Pipeline from SCM: clone repo, run Jenkinsfile.
- `job.setDefinition(flowDef)` — Attach the pipeline definition to the job.

---

### Lesson 2.3.1 — File: `ansible/roles/alb-iam/files/alb-policy.json`

**📄 File:** `ansible/roles/alb-iam/files/alb-policy.json` (summary)

IAM policy document granting the ALB Controller permissions for EC2, ELB, ACM, WAF, Shield, etc. Same content as `terraform/alb-controller-iam-policy.json`. Terraform attaches this policy to `AWSLoadBalancerControllerRole`; Ansible does not apply it. The file is kept in the role for reference or if used by another mechanism.

**Purpose:** IAM policy used by the AWS Load Balancer Controller. In this project the policy is managed by Terraform; this file documents or mirrors it for the alb-iam role context.

---

### Lesson 2.3.2 — File: `ansible/roles/alb-iam/tasks/main.yaml`

**📄 File:** `ansible/roles/alb-iam/tasks/main.yaml`

```yaml
---
- name: Create Kubernetes ServiceAccount manifest for ALB Controller
  ansible.builtin.template:
    src: serviceaccount.yaml.j2
    dest: /tmp/alb-serviceaccount.yaml
    mode: "0644"

- name: Apply ServiceAccount to cluster
  ansible.builtin.shell: /usr/local/bin/kubectl apply -f /tmp/alb-serviceaccount.yaml
  environment:
    KUBECONFIG: /root/.kube/config
    PATH: "/usr/local/bin:/usr/bin:/bin"
  register: sa_apply
  changed_when: true
```

**Purpose:** Renders the ServiceAccount manifest with IRSA annotation and applies it to the cluster. The IAM role and policy are created by Terraform; this role only manages the Kubernetes ServiceAccount.

**Line-by-line:**
- `template` — Renders `serviceaccount.yaml.j2` with `{{ aws_account_id }}` and writes to `/tmp/`.
- `kubectl apply -f` — Applies the ServiceAccount to the EKS cluster.
- `KUBECONFIG` — Uses kubeconfig created by the Jenkins role.

---

### Lesson 2.3.3 — File: `ansible/roles/alb-iam/templates/serviceaccount.yaml.j2`

**📄 File:** `ansible/roles/alb-iam/templates/serviceaccount.yaml.j2`

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: aws-load-balancer-controller
  namespace: kube-system
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::{{ aws_account_id }}:role/AWSLoadBalancerControllerRole
```

**Purpose:** Creates the Kubernetes ServiceAccount used by the AWS Load Balancer Controller. The IRSA annotation tells AWS which IAM role the controller should assume when calling AWS APIs.

**Line-by-line:**
- `apiVersion: v1`, `kind: ServiceAccount` — Standard Kubernetes ServiceAccount.
- `metadata.name: aws-load-balancer-controller` — Must match the name Helm uses for the controller.
- `metadata.namespace: kube-system` — Same namespace as the controller pods.
- `annotations.eks.amazonaws.com/role-arn` — IRSA annotation; EKS injects credentials for this IAM role into pods using this ServiceAccount. `{{ aws_account_id }}` comes from playbook vars.

---

### Lesson 2.4.1 — File: `ansible/roles/helm-install/files/alb-controller-fargate-values.yaml`

**📄 File:** `ansible/roles/helm-install/files/alb-controller-fargate-values.yaml`

```yaml
enableBackendSecurityGroup: false
tolerations:
  - key: eks.amazonaws.com/compute-type
    operator: Equal
    value: fargate
    effect: NoSchedule
```

**Purpose:** Helm values for the AWS Load Balancer Controller on EKS Fargate. Disables the backend security group to avoid ALB reachability issues, and allows pods to run on Fargate nodes.

**Line-by-line:**
- `enableBackendSecurityGroup: false` — Controller uses only the Managed (frontend) SG for ALBs. Avoids attaching the Shared Backend SG, which has no inbound rules and can block ALB → pod traffic.
- `tolerations:` — EKS Fargate nodes have taint `eks.amazonaws.com/compute-type=fargate:NoSchedule`. These tolerations allow the controller to be scheduled there.

---

### Lesson 2.4.2 — File: `ansible/roles/helm-install/files/argocd-fargate-values.yaml`

**📄 File:** `ansible/roles/helm-install/files/argocd-fargate-values.yaml`

```yaml
global:
  tolerations:
    - key: eks.amazonaws.com/compute-type
      operator: Equal
      value: fargate
      effect: NoSchedule
dex:
  enabled: false
repoServer:
  livenessProbe:
    enabled: false
  readinessProbe:
    enabled: false
```

**Purpose:** Helm values for Argo CD on EKS Fargate. Enables scheduling on Fargate and reduces probe-related restarts on slower startup.

**Line-by-line:**
- `global.tolerations` — Same Fargate taint toleration; Argo CD pods can run on Fargate.
- `dex.enabled: false` — Turn off Dex (auth); avoid `server.secretkey` issues; use Argo CD built-in auth.
- `repoServer.livenessProbe.enabled: false` — Fargate startup can be slower; default probes can cause CrashLoopBackOff before the pod is ready.
- `repoServer.readinessProbe.enabled: false` — Same reason; avoids premature restarts during slow startup.

---

### Lesson 2.4.3 — File: `ansible/roles/helm-install/tasks/main.yaml`

**📄 File:** `ansible/roles/helm-install/tasks/main.yaml` (key tasks)

```yaml
---
- name: Ensure kubeconfig uses v1beta1 and exec command uses AWS CLI v2
  ansible.builtin.shell: |
    sed -i 's/v1alpha1/v1beta1/g' /root/.kube/config
    sed -i 's/command: aws/command: \/usr\/local\/bin\/aws/g' ...

- name: Install Helm
  ansible.builtin.shell: curl -fsSL .../get-helm-3 | bash
  creates: /usr/local/bin/helm

- name: Add EKS Helm repo
  ansible.builtin.shell: helm repo add eks https://aws.github.io/eks-charts

- name: Add Argo Helm repo
  ansible.builtin.shell: helm repo add argo https://argoproj.github.io/argo-helm

- name: Remove ALB webhook (so ArgoCD install can create Services)
  ansible.builtin.shell: kubectl delete mutatingwebhookconfiguration ...

- name: Copy ArgoCD Fargate values / Install ArgoCD
  ansible.builtin.copy: src: argocd-fargate-values.yaml dest: /tmp/...
  ansible.builtin.shell: helm upgrade --install argocd argo/argo-cd -n argocd -f /tmp/argocd-fargate-values.yaml

- name: Wait for ArgoCD deployments and pods
  ansible.builtin.shell: kubectl wait --for=condition=available ... -n argocd

- name: Apply ArgoCD Application
  ansible.builtin.copy: src: application.yaml dest: /tmp/argocd-application.yaml
  ansible.builtin.shell: kubectl apply -f /tmp/argocd-application.yaml

- name: Get EKS VPC ID
  ansible.builtin.shell: aws eks describe-cluster --query 'cluster.resourcesVpcConfig.vpcId' ...

- name: Install AWS Load Balancer Controller
  ansible.builtin.shell: helm upgrade --install aws-load-balancer-controller ... --set vpcId={{ eks_vpc_id_out.stdout }}
```

**Purpose:** Installs Helm, Argo CD, and the AWS Load Balancer Controller in the EKS cluster. Fixes kubeconfig for Helm, waits for Argo CD, applies the Application manifest, then installs the ALB controller with VPC ID for Fargate.

**Line-by-line:**
- `sed v1alpha1 → v1beta1` — Fix kubeconfig exec plugin version for Helm.
- `sed command: aws → /usr/local/bin/aws` — Use AWS CLI v2 for EKS auth.
- `helm repo add eks/argo` — Add EKS and Argo Helm repos.
- `kubectl delete mutatingwebhookconfiguration` — Remove leftover ALB webhook so Argo CD can create Services.
- `helm upgrade --install argocd` — Install Argo CD with Fargate values.
- `kubectl wait` — Wait for Argo CD deployments and pods to be ready.
- `kubectl apply -f argocd-application.yaml` — Deploy the Argo CD Application (syncs `k8s/` from Git).
- `aws eks describe-cluster --query vpcId` — Get VPC ID; ALB controller on Fargate needs it (no instance metadata).
- `helm upgrade --install aws-load-balancer-controller` — Install ALB controller with `vpcId` and Fargate values.

---

## CHAPTER 3 — The Application

This chapter describes the simple **Flask** application in `app-project/`:

- `app.py` — defines the Flask app, the `/` route, and runs on port 5000.
- `requirements.txt` — lists Python dependencies (currently just Flask).
- `templates/index.html` — the HTML page rendered at `/`.
- `static/style.css` — basic styling.

It shows how the application is structured, how Flask routes work, and how these files are copied and run inside the Docker container (see CHAPTER 4).

---

### Lesson 3.1 — File: `app-project/app.py`

**📄 File:** `app-project/app.py`

```python
from flask import Flask, render_template

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
```

**Purpose:** Flask app with one route `/` that renders `index.html`. `host="0.0.0.0"` lets the app accept external connections inside the container; `port=5000` is exposed to the Service and Ingress.

**Line-by-line:**
- `from flask import Flask, render_template` — Imports Flask and `render_template` to serve HTML.
- `app = Flask(__name__)` — Creates the Flask app instance.
- `@app.route("/")` — Registers the root path as the route.
- `def index(): return render_template("index.html")` — Serves `templates/index.html` for `/`.
- `if __name__ == "__main__"` — Runs the app only when the script is executed directly.
- `app.run(host="0.0.0.0", port=5000)` — Binds to all interfaces (`0.0.0.0`) so it is reachable from outside the container; uses port 5000, which the K8s Service and Ingress reference.

---

### Lesson 3.2 — File: `app-project/requirements.txt`

**📄 File:** `app-project/requirements.txt`

```text
flask
```

**Purpose:** Declares the app’s Python dependency. Docker uses this file to install packages before copying app code so dependency layers can be cached.

**Line-by-line:**
- `flask` — Flask web framework; required for the app. Version can be pinned (e.g. `flask>=3.0`) for reproducibility.

---

### Lesson 3.3 — File: `app-project/templates/index.html`

**📄 File:** `app-project/templates/index.html`

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>NTI x iVolve Graduation Project</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
</head>
<body>
    <div class="container">
        <h1>DevOps Graduation Project</h1>
        <h2>In Collaboration with iVolve Technologies</h2>
        ...
    </div>
</body>
</html>
```

**Purpose:** HTML template for the landing page. Uses Flask’s `url_for` to link to static assets and shows the graduation project title and logos.

**Line-by-line:**
- `<!DOCTYPE html>`, `<html lang="en">` — Standard HTML5 structure.
- `{{ url_for('static', filename='style.css') }}` — Jinja2 expression; Flask generates the correct URL for `static/style.css`.
- `.container` — Main layout wrapper.
- Content includes NTI/iVolve branding and description.

---

## CHAPTER 4 — Containerization with Docker

This chapter breaks down `docker/Dockerfile` line‑by‑line:

- Base image (`python:3.10-slim`), why slim images are preferred.
- Working directory (`/app`) and why using a dedicated directory is good practice.
- Layer ordering for efficient caching:
  - Copy `requirements.txt` and run `pip install` before copying app code.
- Exposing port 5000 and using `CMD ["python", "app.py"]`.

It also discusses best practices (single vs multi‑stage builds, image size, reproducibility).

---

### Lesson 4.1 — File: `docker/Dockerfile`

**📄 File:** `docker/Dockerfile`

```dockerfile
FROM python:3.10-slim
WORKDIR /app
COPY app-project/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app-project/ .
EXPOSE 5000
CMD ["python", "app.py"]
```

**Purpose:** Builds the Flask app image used by Jenkins and EKS. Uses layered caching and a slim base image for a small, reproducible image.

**Line-by-line:**
- `FROM python:3.10-slim` — Slim Debian-based image; smaller than `python:3.10` and sufficient for Flask.
- `WORKDIR /app` — Sets the working directory for following commands and for the app runtime.
- `COPY app-project/requirements.txt .` — Copies only the requirements file first so `pip install` can be cached if dependencies do not change.
- `RUN pip install --no-cache-dir -r requirements.txt` — Installs dependencies; `--no-cache-dir` keeps the image smaller.
- `COPY app-project/ .` — Copies the rest of the app; this layer changes more often than the pip layer.
- `EXPOSE 5000` — Documents that the app listens on 5000; does not publish the port.
- `CMD ["python", "app.py"]` — Default command; starts the Flask app when the container runs.

---

## CHAPTER 5 — CI/CD with Jenkins

This chapter explains:

- The **Declarative Pipeline** in `Jenkinsfile`:
  - Each stage (Checkout, BuildImage, ScanImage, PushImage, RemoveImageLocally, UpdateManifests, PushManifests).
  - Environment variables (ECR registry, image name, region, GitHub credentials).
  - Post actions (always/success/failure).
- The **Jenkins Shared Library** in `Shared-Library/vars/`:
  - `buildImage.groovy` — wraps `docker build`.
  - `scanImage.groovy` — installs/uses Trivy.
  - `pushImageECR.groovy` — logs in to and pushes to ECR.
  - `updateManifests.groovy` — updates `k8s/deployment.yaml`.
  - `pushManifests.groovy` — commits and pushes manifests to GitHub.
  - `removeImageLocally.groovy` — cleans up images on the Jenkins node.

It shows how using a Shared Library keeps the Jenkinsfile short and readable while centralizing complex shell logic.

---

### Lesson 5.1 — File: `Jenkinsfile`

**📄 File:** `Jenkinsfile` (excerpt)

```groovy
@Library('ivolve-shared-library@main') _

pipeline {
    agent any
    environment {
        IMAGE_TAG    = "${env.BUILD_NUMBER}"
        ECR_REGISTRY = "183631347882.dkr.ecr.us-east-1.amazonaws.com"
        ECR_IMAGE    = "${ECR_REGISTRY}/ivolve-app"
        AWS_REGION   = "us-east-1"
        GITHUB_CREDENTIAL_ID = "github-credentials"
        GITHUB_REPO_URL      = "https://github.com/tarek-code/CloudDevOpsProject.git"
    }
    stages {
        stage('Checkout') { ... }
        stage('BuildImage') { buildImage(imageName, workDir, 'docker/Dockerfile') }
        stage('ScanImage') { scanImage(imageName) }
        stage('PushImage') { pushImageECR(imageName, AWS_REGION) }
        stage('RemoveImageLocally') { removeImageLocally(imageName) }
        stage('UpdateManifests') { updateManifests(imageUrl, manifestsDir) }
        stage('PushManifests') { pushManifests(...) }
    }
    post { always { deleteDir() } success { ... } failure { ... } }
}
```

**Purpose:** Declarative pipeline using `ivolve-shared-library`. Runs stages: Checkout → BuildImage → ScanImage → PushImage → RemoveImageLocally → UpdateManifests → PushManifests. Environment variables define ECR and GitHub.

**Line-by-line:**
- `@Library('ivolve-shared-library@main') _` — Loads the Shared Library from branch `main`; `_` means no import alias.
- `agent any` — Runs on any available Jenkins agent.
- `IMAGE_TAG = "${env.BUILD_NUMBER}"` — Uses build number as image tag.
- `ECR_REGISTRY`, `ECR_IMAGE` — ECR URL and image name; must match Terraform ECR and Jenkins IAM.
- `GITHUB_CREDENTIAL_ID`, `GITHUB_REPO_URL` — Jenkins credential for push; repo URL for manifests.
- `stage('Checkout')` — Clones the app repo (via SCM or manual clone).
- `stage('BuildImage')` — Calls `buildImage(...)` to build the Docker image.
- `stage('ScanImage')` — Calls `scanImage(...)` for Trivy vulnerability scan.
- `stage('PushImage')` — Calls `pushImageECR(...)` to push to ECR.
- `stage('RemoveImageLocally')` — Calls `removeImageLocally(...)` to free disk.
- `stage('UpdateManifests')` — Calls `updateManifests(...)` to update `k8s/deployment.yaml`.
- `stage('PushManifests')` — Calls `pushManifests(...)` to commit and push to GitHub.
- `post { always { deleteDir() } }` — Always deletes workspace after the run.

---

### Lesson 5.2.1 — File: `Shared-Library/vars/buildImage.groovy`

**📄 File:** `Shared-Library/vars/buildImage.groovy`

```groovy
def call(String imageName, String workDir = '.', String dockerfilePath = null) {
    dir(workDir) {
        script {
            def dockerfile = dockerfilePath ?: 'Dockerfile'
            if (!fileExists(dockerfile)) { error("Dockerfile not found: ${workDir}/${dockerfile}") }
            def buildCmd = dockerfilePath
                ? "docker build -f ${dockerfilePath} -t ${imageName} ."
                : "docker build -t ${imageName} ."
            sh """
                ${buildCmd}
                docker tag ${imageName} ${imageName.split(':')[0]}:latest
            """
        }
    }
}
```

**Purpose:** Builds the Docker image and tags it as `latest`. Centralizes the build command in the Shared Library.

**Line-by-line:**
- `def call(String imageName, ...)` — Groovy callable; invoked as `buildImage(imageName, workDir, dockerfilePath)`.
- `dir(workDir)` — Executes inside the given working directory (e.g. project root).
- `dockerfilePath ?: 'Dockerfile'` — Uses provided path or default `Dockerfile`.
- `docker build -f ${dockerfilePath} -t ${imageName} .` — Builds using a custom Dockerfile (e.g. `docker/Dockerfile`).
- `docker tag ${imageName} ${imageName.split(':')[0]}:latest` — Tags the same image as `latest` for convenience.

---

### Lesson 5.2.2 — File: `Shared-Library/vars/scanImage.groovy`

**📄 File:** `Shared-Library/vars/scanImage.groovy` (excerpt)

```groovy
def call(String imageName) {
    script {
        def trivyPath = sh(script: 'which trivy || echo "not found"', returnStdout: true).trim()
        if (trivyPath == 'not found') {
            // Install Trivy via direct download (pinned v0.69.1)
            TRIVY_TAG=v0.69.1
            wget ... trivy_0.69.1_Linux-64bit.tar.gz
        }
        sh "trivy image --exit-code 0 --severity HIGH,CRITICAL ${imageName}"
    }
}
```

**Purpose:** Scans the built image with Trivy for HIGH/CRITICAL vulnerabilities. Installs Trivy if needed; does not fail the pipeline on findings (`--exit-code 0`).

**Line-by-line:**
- `which trivy || echo "not found"` — Checks if Trivy is installed.
- If not found: installs Trivy (pinned `v0.69.1`) via direct download for reliability.
- `trivy image --exit-code 0 --severity HIGH,CRITICAL` — Scans image; exit 0 so findings do not fail the build; limits to HIGH and CRITICAL severities.

---

### Lesson 5.2.3 — File: `Shared-Library/vars/pushImageECR.groovy`

**📄 File:** `Shared-Library/vars/pushImageECR.groovy`

```groovy
def call(String imageName, String region = 'us-east-1') {
    script {
        def registry = (imageName =~ /^([^\/]+)/)[0][1]
        sh """
            aws ecr get-login-password --region ${region} | docker login --username AWS --password-stdin ${registry}
        """
        sh "docker push ${imageName}"
    }
}
```

**Purpose:** Logs into ECR and pushes the image. Uses the instance role for auth.

**Line-by-line:**
- `def registry = (imageName =~ /^([^\/]+)/)[0][1]` — Extracts registry from image name (e.g. `183631347882.dkr.ecr.us-east-1.amazonaws.com`).
- `aws ecr get-login-password | docker login --username AWS --password-stdin` — Gets ECR token and logs Docker into ECR.
- `docker push ${imageName}` — Pushes the image to ECR.

---

### Lesson 5.2.4 — File: `Shared-Library/vars/updateManifests.groovy`

**📄 File:** `Shared-Library/vars/updateManifests.groovy`

```groovy
def call(String imageUrl, String manifestsDir = 'k8s') {
    dir(manifestsDir) {
        script {
            sh """
                sed -i -E 's|^([[:space:]]*image:[[:space:]]*).*|\\1${imageUrl}|' deployment.yaml
                grep -q "image: ${imageUrl}" deployment.yaml || echo "Warning: Image update may have failed"
            """
        }
    }
}
```

**Purpose:** Updates the `image:` field in `k8s/deployment.yaml` with the newly built image URL so Argo CD deploys the new version.

**Line-by-line:**
- `dir(manifestsDir)` — Runs in `k8s/` by default.
- `sed -i -E 's|^([[:space:]]*image:[[:space:]]*).*|\\1${imageUrl}|'` — Replaces the image value while keeping indentation; `-i` edits in place.
- `grep -q "image: ${imageUrl}"` — Checks that the update was applied.

---

### Lesson 5.2.5 — File: `Shared-Library/vars/pushManifests.groovy`

**📄 File:** `Shared-Library/vars/pushManifests.groovy` (excerpt)

```groovy
def call(String commitMessage = null, String manifestsDir = 'k8s', String branch = null, String credentialId = null, String repoUrl = null) {
    def msg = commitMessage ?: "CI: update manifests for build ${env.BUILD_NUMBER}"
    def targetBranch = branch ?: (env.BRANCH_NAME ?: 'main')
    sh """
        git config user.email 'jenkins@localhost'
        git config user.name 'Jenkins'
        git add ${manifestsDir}/
        git diff --staged --quiet || git commit -m '${msg}'
    """
    withCredentials([usernamePassword(credentialsId: credentialId, ...)]) {
        sh "git push origin HEAD:${targetBranch}"
    }
}
```

**Purpose:** Commits updated manifests and pushes them to GitHub so Argo CD can sync the new image. Uses Jenkins credentials for authentication.

**Line-by-line:**
- `commitMessage ?: "CI: update manifests..."` — Uses provided message or a default.
- `targetBranch` — Target branch (e.g. `main`).
- `git add ${manifestsDir}/` — Stages `k8s/` (or given dir).
- `git diff --staged --quiet || git commit` — Commits only if there are changes.
- `withCredentials` — Uses Jenkins credential for Git push.

---

### Lesson 5.2.6 — File: `Shared-Library/vars/removeImageLocally.groovy`

**📄 File:** `Shared-Library/vars/removeImageLocally.groovy`

```groovy
def call(String imageName) {
    script {
        def imageRepo = imageName.split(':')[0]
        sh """
            docker rmi ${imageName} || echo "Image ${imageName} not found"
            docker rmi ${imageRepo}:latest || echo "Image ${imageRepo}:latest not found"
        """
    }
}
```

**Purpose:** Removes the built image and its `:latest` tag from the local Docker daemon to free disk space on the Jenkins agent.

**Line-by-line:**
- `imageRepo = imageName.split(':')[0]` — Extracts repository without tag (e.g. `183631347882.dkr.ecr.us-east-1.amazonaws.com/ivolve-app`).
- `docker rmi ${imageName}` — Removes the tagged image.
- `docker rmi ${imageRepo}:latest` — Removes the `:latest` tag created by buildImage.

---

#### 5.x — What the Jenkins Pipeline Looks Like

1. Push code changes to GitHub (app, Dockerfile, or manifests).  
2. Jenkins automatically runs the pipeline: *Checkout → BuildImage → ScanImage → PushImage → UpdateManifests → PushManifests → Cleanup*.  
3. In the Jenkins UI, confirm that all stages are green and the build completed successfully.

![Jenkins Pipeline](Screenshots/jenkins-pipline-created-after-ansible-finished.png)

---

## CHAPTER 6 — GitOps with ArgoCD

This chapter covers:

- What **GitOps** means: Git as the source of truth, cluster reconciles to Git.
- How `argocd/application.yaml`:
  - Points Argo CD to this GitHub repo.
  - Tells it to watch the `k8s/` folder on branch `main`.
  - Configures automated sync, prune, and self‑heal.
- How Argo CD reacts to new commits pushed by Jenkins and updates the EKS cluster accordingly.

---

### Lesson 6.1 — File: `argocd/application.yaml`

**📄 File:** `argocd/application.yaml`

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: ivolve-app
  namespace: argocd
  finalizers:
    - resources-finalizer.argocd.argoproj.io
spec:
  project: default
  source:
    repoURL: https://github.com/tarek-code/CloudDevOpsProject.git
    targetRevision: main
    path: k8s
  destination:
    server: https://kubernetes.default.svc
    namespace: ivolve
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - CreateNamespace=true
      - PruneLast=true
```

**Purpose:** Defines the Argo CD Application that watches the `k8s/` folder in Git and syncs it to the EKS cluster. Enables automated sync, prune, and self-heal for GitOps.

**Line-by-line:**
- `apiVersion: argoproj.io/v1alpha1`, `kind: Application` — Argo CD Application CRD.
- `metadata.name: ivolve-app` — Application name in Argo CD UI.
- `metadata.namespace: argocd` — Application CR lives in the argocd namespace.
- `finalizers: resources-finalizer.argocd.argoproj.io` — Ensures resources are cleaned up when the Application is deleted.
- `spec.project: default` — Uses the default Argo CD project.
- `spec.source.repoURL` — Git repo URL (same repo as the app).
- `spec.source.targetRevision: main` — Branch to watch.
- `spec.source.path: k8s` — Path inside the repo containing manifests.
- `spec.destination.server: https://kubernetes.default.svc` — Target cluster (in-cluster API).
- `spec.destination.namespace: ivolve` — Target namespace for deployed resources.
- `syncPolicy.automated.prune: true` — Removes resources no longer in Git.
- `syncPolicy.automated.selfHeal: true` — Reverts manual changes to match Git.
- `syncOptions: CreateNamespace=true` — Creates the `ivolve` namespace if missing.
- `syncOptions: PruneLast=true` — Deletes pruned resources after sync.

---

#### 6.x — Argo CD Showing the App in Sync

1. Open the Argo CD web UI and log in.  
2. Find the `ivolve-app` (or your app) in the **Applications** list.  
3. Confirm the status is **Healthy** and **Synced**, and drill into the tree view to see all Kubernetes resources.

![Argo CD Application](Screenshots/jekins-console-output.png)

---

## CHAPTER 7 — Kubernetes Manifests

This chapter walks through:

- `k8s/namespace.yaml` — creation of `ivolve` namespace.
- `k8s/deployment.yaml` — Deployment spec (replicas, pod template, container, probes, resources).
- `k8s/service.yaml` — ClusterIP service mapping port 80 → 5000.
- `k8s/ingress.yaml` — Ingress definition with ALB annotations (scheme, target-type, listen-ports, inbound-cidrs).

You’ll see how these manifests represent the final, desired state that Argo CD syncs to EKS.

---

### Lesson 7.1 — File: `k8s/namespace.yaml`

**📄 File:** `k8s/namespace.yaml`

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: ivolve
```

**Purpose:** Creates the `ivolve` namespace for the app. Must match the Fargate profile selector and Argo CD destination namespace.

**Line-by-line:**
- `apiVersion: v1`, `kind: Namespace` — Standard Kubernetes Namespace resource.
- `metadata.name: ivolve` — Namespace name; used by Fargate profile, Argo CD, and all app resources.

---

### Lesson 7.2 — File: `k8s/deployment.yaml`

**📄 File:** `k8s/deployment.yaml`

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ivolve-app
  namespace: ivolve
spec:
  replicas: 3
  selector:
    matchLabels:
      app: ivolve-app
  template:
    metadata:
      labels:
        app: ivolve-app
    spec:
      containers:
        - name: ivolve-app
          image: 183631347882.dkr.ecr.us-east-1.amazonaws.com/ivolve-app:4
          ports:
            - containerPort: 5000
          resources:
            requests: { cpu: 100m, memory: 128Mi }
            limits: { cpu: 200m, memory: 256Mi }
          livenessProbe:
            httpGet:
              path: /
              port: 5000
```

**Purpose:** Defines the Flask app Deployment. Jenkins updates the `image` tag; Argo CD syncs it to EKS; Fargate runs the pods.

**Line-by-line:**
- `replicas: 3` — Runs 3 pod replicas for availability.
- `selector.matchLabels: app: ivolve-app` — Selects pods with label `app=ivolve-app`.
- `template.metadata.labels` — Same labels as selector.
- `image:` — ECR image; Jenkins updates the tag each build.
- `containerPort: 5000` — Port the Flask app listens on.
- `resources` — Requests and limits for Fargate sizing.
- `livenessProbe.httpGet path: / port: 5000` — Liveness check on the app root; restarts unhealthy pods.

---

### Lesson 7.3 — File: `k8s/service.yaml`

**📄 File:** `k8s/service.yaml`

```yaml
apiVersion: v1
kind: Service
metadata:
  name: ivolve-app-service
  namespace: ivolve
spec:
  type: ClusterIP
  selector:
    app: ivolve-app
  ports:
    - port: 80
      targetPort: 5000
```

**Purpose:** Exposes the Deployment as a ClusterIP Service. The Ingress (via ALB) sends traffic to this Service on port 80, which forwards to the containers on port 5000.

**Line-by-line:**
- `type: ClusterIP` — Cluster-internal only; Ingress/ALB uses it as backend.
- `selector: app: ivolve-app` — Targets pods with that label (Deployment pods).
- `port: 80` — Port the Service listens on; Ingress backend references this.
- `targetPort: 5000` — Port on the pod containers; matches Flask.

---

### Lesson 7.4 — File: `k8s/ingress.yaml`

**📄 File:** `k8s/ingress.yaml`

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ivolve-app-ingress
  namespace: ivolve
  annotations:
    kubernetes.io/ingress.class: alb
    alb.ingress.kubernetes.io/scheme: internet-facing
    alb.ingress.kubernetes.io/target-type: ip
    alb.ingress.kubernetes.io/listen-ports: '[{"HTTP": 80}]'
    alb.ingress.kubernetes.io/inbound-cidrs: 0.0.0.0/0,::/0
spec:
  rules:
    - http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: ivolve-app-service
                port:
                  number: 80
```

**Purpose:** Ingress resource that instructs the AWS Load Balancer Controller to create an internet-facing ALB. Routes HTTP traffic on port 80 to the Service.

**Line-by-line:**
- `kubernetes.io/ingress.class: alb` — Use the AWS ALB controller.
- `alb.ingress.kubernetes.io/scheme: internet-facing` — ALB in public subnets for external access.
- `alb.ingress.kubernetes.io/target-type: ip` — Required for Fargate; target pod IPs directly.
- `alb.ingress.kubernetes.io/listen-ports: '[{"HTTP": 80}]'` — Listener on port 80.
- `alb.ingress.kubernetes.io/inbound-cidrs: 0.0.0.0/0,::/0` — Allow all sources.
- `path: /`, `pathType: Prefix` — All paths go to the backend.
- `backend.service.name: ivolve-app-service` — Backend Service.
- `backend.service.port.number: 80` — Service port.

---

#### 7.x — Pods Running on EKS Fargate

1. From a machine with kubeconfig (Jenkins EC2 or your laptop), run:

```bash
kubectl get pods -n ivolve
```

2. All pods should be in **Running** state, scheduled onto Fargate.  
3. If pods are pending, check IAM (IRSA), Fargate profiles, and namespace labels.

![EKS Pods](Screenshots/cordns-addons-in-eks.png)

---

## CHAPTER 8 — Architecture Deep Dive

This chapter combines:

- A **Mermaid diagram** showing the entire system:
  - Dev → GitHub → Jenkins → ECR → ArgoCD → EKS → ALB → User.
- A detailed **network architecture** discussion:
  - VPC, subnets, route tables, NACLs, security groups.
  - Where ALB and Fargate pods live.
- **IAM & security architecture**:
  - IAM roles for Jenkins and ALB controller.
  - IRSA flow for ALB controller.
- A step‑by‑step **CI/CD execution trace** from `git push` to “page loads in browser”.

It is intended for readers who already understand the individual pieces and want a holistic mental model of the whole platform.

---

### 8.5 — Final Result (What You Actually See)

After you follow all the steps in this README, the **final result** looks like this:

- **Jenkins**: a multi‑stage pipeline that automatically builds, scans, pushes, and deploys your app.  
- **Argo CD**: an app pane that shows your Kubernetes resources in sync and healthy.  
- **The App**: a Python/Flask web page being served through an AWS ALB to EKS Fargate pods.

Visually:

| Jenkins Pipeline View | ALB & Target Group | Final App Result |
| --------------------- | ------------------ | ---------------- |
| ![Jenkins Pipeline](Screenshots/jenkins-pipline-created-after-ansible-finished.png) | ![ALB & Target Group](Screenshots/aws-alb-info.png) | ![Final Result](Screenshots/final-result-from-alb.png) |

Think of this as the **“victory screen”** for the project: it proves that Terraform, Ansible, Jenkins, Docker, Trivy, Argo CD, Kubernetes, and AWS networking are all working together end‑to‑end.

---

## CHAPTER 9 — Problems & Solutions

This chapter documents the real issues encountered while building and debugging this project, and how they were solved. Treat it as a **troubleshooting playbook** and also as a **learning diary**.

### Problem #1: VPC Destroy Fails (`DependencyViolation`)

- **What happened:**  
`terraform destroy` failed with error:  
`The vpc 'vpc-xxx' has dependencies and cannot be deleted.`
- **Why it happened:**  
Resources created outside Terraform (ALBs, NAT gateways, VPC endpoints) were still attached to the VPC, so AWS refused to delete it.
- **How it was solved:**  
  - Wrote `terraform/scripts/cleanup-vpc-dependencies.sh` to:
    - Delete ALBs, NLBs, classic ELBs.
    - Delete NAT gateways.
    - Delete VPC endpoints.
    - Wait for ENIs to detach.
  - Ran the script with the VPC ID.
  - Re‑ran `terraform destroy`.
- **What to learn:**  
Always clean up out‑of‑band resources before destroying the VPC, or give Terraform modules full control over ALB/NAT/VPC endpoints to avoid drift.

### Problem #2: ALB Times Out, Targets Healthy (NACL Missing Port 80)

- **What happened:**  
  - Target group showed all targets **Healthy**.
  - Browser and `curl` (even from Jenkins EC2 in same VPC) got `ERR_CONNECTION_TIMED_OUT`.
- **Why it happened:**  
  - Public subnet NACL did not have an inbound rule for TCP port 80.
  - NACL is stateless and denies all traffic not explicitly allowed.
- **How it was solved:**  
  - Added inbound NACL rule 125 allowing TCP 80 from `0.0.0.0/0`.
  - Encoded this in Terraform `public_inbound_acl_rules`.
  - Re‑ran `terraform apply`.
- **What to learn:**  
When ALB targets are healthy but connectivity fails:
  - Check NACLs (especially when you use custom NACLs).
  - Don’t rely solely on security groups; both NACLs and SGs must allow traffic.

---

### Problem #3: Jenkins EC2 SSH — Forgot to Download Key Pair / Wrong Key

- **What happened:**  
  - You created an EC2 key pair in AWS but **forgot to download the `.pem` file** (or later used the wrong `.pem`).  
  - SSH attempts from WSL/Ubuntu to Jenkins EC2 failed with:  
  `Permission denied (publickey,gssapi-keyex,gssapi-with-mic).`
- **Why it happened:**  
  - AWS only shows the private key **once** at creation time.  
  - If you don’t download or you lose it, you cannot recover it.  
  - Using a `.pem` that does not match the EC2 instance’s key pair will always fail SSH.
- **How it was solved:**  
  1. Created a **new key pair** in AWS (e.g., `Jenkins_key`), this time saving the `.pem`.
  2. Updated `terraform/terraform.tfvars` to point `jenkins_key_name` to the new key name.
  3. Re‑applied Terraform so the **Jenkins EC2 instance was recreated** with the new key pair.
  4. Copied the `.pem` into WSL and fixed permissions:
    ```bash
     mkdir -p ~/.ssh
     cp /mnt/c/Users/<YourUser>/Downloads/Jenkins_key.pem ~/.ssh/
     chmod 600 ~/.ssh/Jenkins_key.pem
     ssh -i ~/.ssh/Jenkins_key.pem ec2-user@<JENKINS_PUBLIC_IP>
    ```
- **What to learn:**  
  - Always download and safely store the `.pem` when creating EC2 key pairs.  
  - Terraform ties instances to `jenkins_key_name`; to change the SSH key, you usually recreate the instance.  
  - On Linux/WSL, private keys must have `chmod 600` or SSH will refuse them.

---

### Problem #4: AWS Account ID Hard‑Coded / Mismatch in Trust Policy

- **What happened:**  
  - Some IAM trust policies (e.g. `terraform/trust-policy.json`) still referenced an **old AWS account ID**.  
  - After switching to a new account (`183631347882`), the trust policy used the wrong account ID and IRSA didn’t work correctly.
- **Why it happened:**  
  - The trust policy JSON was originally created for another account and had `arn:aws:iam::<OLD_ACCOUNT_ID>:oidc-provider/...`.  
  - Updating `terraform.tfvars` alone is not enough if JSON files contain hard‑coded ARNs.
- **How it was solved:**  
  - Searched the repo for the old account ID and updated it to the new one (`183631347882`).  
  - Specifically fixed `terraform/trust-policy.json` so the `Federated` principal pointed to the correct account’s OIDC provider ARN.  
  - Re‑applied Terraform and re‑ran Ansible to ensure ALB controller IRSA worked.
- **What to learn:**  
  - When changing AWS accounts, search for hard‑coded ARNs (not just Terraform variables).  
  - Prefer generating ARNs from variables where possible; if you must keep JSON, make sure to update it carefully.

---

### Problem #5: Jenkins EC2 Lacked Permissions for ELB/EC2 Describe (Diagnostics)

- **What happened:**  
  - Running AWS CLI commands on Jenkins EC2 like `aws elbv2 describe-load-balancers` or `aws ec2 describe-route-tables` failed with `AccessDenied`.  
  - This blocked diagnosing ALB and subnet issues from the host.
- **Why it happened:**  
  - The Jenkins EC2 IAM policy only had permissions for ECR and EKS (`DescribeCluster`), not for ELB/EC2 `Describe`*.  
  - The AWS CLI uses the instance profile role, so missing permissions mean those commands fail.
- **How it was solved:**  
  - Extended `aws_iam_role_policy.jenkins_ecr_eks` in `terraform/main.tf` with:
    ```hcl
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
    ```
  - Ran `terraform apply`.  
  - Re‑ran the AWS CLI diagnostics successfully.
- **What to learn:**  
  - Always give your “ops” EC2 roles **read‑only** Describe permissions for the resources you need to debug.  
  - Keep IAM minimal but practical; debugging blind is much harder.

---

### Problem #6: AWS Load Balancer Controller Needed IAM Role & IRSA

- **What happened:**  
  - The ALB Ingress Controller (AWS Load Balancer Controller) could not create load balancers or manage security groups until IAM and IRSA were properly configured.
- **Why it happened:**  
  - The controller runs in Kubernetes and calls AWS APIs; without a valid IAM role and trust relationship, AWS rejects its calls.  
  - Initially, trust policy / policy mismatches (account ID, OIDC issuer) prevented successful IRSA.
- **How it was solved:**  
  - Created OIDC provider and IAM role/policy in Terraform:
    - `aws_iam_openid_connect_provider.eks` for the EKS cluster OIDC.  
    - `aws_iam_policy.alb_controller` loading `alb-controller-iam-policy.json`.  
    - `aws_iam_role.alb_controller` with trust policy pointing to ServiceAccount `kube-system/aws-load-balancer-controller`.  
    - Attached the policy to the role.
  - In Ansible:
    - Created the matching ServiceAccount with `eks.amazonaws.com/role-arn` annotation.  
    - Installed the controller with Helm (`helm-install` role).
- **What to learn:**  
  - AWS controllers (ALB, EBS CSI, etc.) require **IRSA** correctly set up (OIDC provider, trust policy, IAM policy).  
  - Keep trust policy and ServiceAccount configuration in sync (namespace, SA name, cluster OIDC URL).

---

### Problem #7: Argo CD and CoreDNS on Fargate

- **What happened:**  
  - When using Fargate for all pods (including Argo CD and app pods), DNS resolution or pod scheduling could be unreliable without CoreDNS and proper Fargate selectors.
- **Why it happened:**  
  - Fargate requires:
    - Private subnets.
    - CoreDNS running and reachable in those subnets.
  - Without the CoreDNS addon configured and Fargate profile selectors including required namespaces, some components may not start correctly.
- **How it was solved:**  
  - In Terraform:
    - Created Fargate profile with selectors for `kube-system`, `default`, `ivolve`, and `argocd`.  
    - Installed `aws_eks_addon.coredns` with long timeouts and `OVERWRITE` conflict resolution.
  - In Ansible:
    - Installed Argo CD via Helm `argocd-fargate-values.yaml` with Fargate tolerations.
- **What to learn:**  
  - When using EKS Fargate, always ensure:
    - CoreDNS addon is installed and working.  
    - The namespaces you use (like `argocd`, `ivolve`) are covered by Fargate selectors.

---

### Problem #8: Jenkins Shared Library & Pipeline Not Auto‑Configured

- **What happened:**  
  - Initially, Jenkins did not automatically know about the Shared Library or have a pipeline job configured. The user would have to click in the UI, which is error‑prone.
- **Why it happened:**  
  - By default, Jenkins requires manual configuration:
    - Global Pipeline Libraries.
    - Credentials.
    - Pipeline jobs.
- **How it was solved:**  
  - Used Ansible Jenkins role with Groovy init scripts:
    - `global-shared-library.groovy.j2`:
      - Creates/updates GitHub credentials (if provided via vault/extra-vars).
      - Configures Global Pipeline Library (`ivolve-shared-library`) pointing to this repo and `Shared-Library` path.
    - `seed-pipeline-job.groovy.j2`:
      - Creates/updates a seed pipeline job (`CloudDevOpsProject-pipeline`) that uses this repo + `Jenkinsfile`.
  - Restarted Jenkins via Ansible handler to apply changes.
- **What to learn:**  
  - Use **JCasC** (Configuration as Code) and init scripts to fully automate Jenkins configuration.  
  - Treat Jenkins UI as “read‑only”; all config should be in code and replayable.

---

### Problem #9: WSL Key Permissions for SSH (chmod 600)

- **What happened:**  
  - The SSH private key `.pem` was copied into WSL, but SSH still refused to use it.
- **Why it happened:**  
  - OpenSSH on Linux requires private keys to have strict permissions (`0600` or more restrictive).  
  - If the file is world or group‑readable, SSH will reject it:  
  `Bad permissions on private key file`.
- **How it was solved:**  
  - Ran:
    ```bash
    chmod 600 ~/.ssh/Jenkins_key.pem
    ssh -i ~/.ssh/Jenkins_key.pem ec2-user@<JENKINS_PUBLIC_IP>
    ```
  - Confirmed successful SSH.
- **What to learn:**  
  - Always fix permissions after copying keys into WSL or Linux: `chmod 600`.  
  - This is a common hurdle when moving from Windows to WSL.

---

## CHAPTER 10 — Appendix: Original Documentation

### 10.1 — ALB Security Groups Reference

> This consolidates the previous `docs/ALB-SECURITY-GROUPS.md`.

- AWS Load Balancer Controller uses:
  - **Frontend (Managed) SGs**:
    - One per ALB.
    - Controls **clients → ALB** traffic.
    - By default: inbound from `inbound-cidrs` to `listen-ports`.
  - **Backend (Shared) SGs**:
    - Shared across load balancers.
    - Used as the **source** in rules added to target ENI/instance SGs (ALB → target).
    - Not intended to have 0.0.0.0/0 inbound.
- This project sets `enableBackendSecurityGroup: false` in Helm values:
  - ALB only uses Managed SG.
  - Backend rules for pods use the Managed SG as the source.
  - Simplifies debugging: only one SG matters for client inbound (Managed).

### 10.2 — ALB Troubleshooting: Timeout Issues

> This consolidates the previous `docs/ALB-TROUBLESHOOT-TIMEOUT.md`.

Common checks:

1. **Curl from EC2 in same VPC**
  - If `HTTP 200` → ALB + targets OK; problem is public access (ALB in private subnets, SG, or NACL).
  - If timeout → ALB not reachable even internally; check listeners, SGs, NACL.
2. **ALB subnets**
  - Must be in subnets with route: `0.0.0.0/0 → igw-...` (public).
  - For internet‑facing ALB, controller uses subnets tagged `kubernetes.io/role/elb=1`.
3. **ALB SGs**
  - At least one SG must allow:
    - TCP 80 from `0.0.0.0/0` (HTTP).
4. **Public NACL**
  - Inbound:
    - Allow TCP 80 from `0.0.0.0/0`.
  - Outbound:
    - Allow ephemeral ports back out.
5. **Target groups**
  - Targets healthy?
  - Health check path `/`, port 5000 (or traffic‑port) if the app listens on 5000.

---

## CHAPTER 11 — About the Author & Acknowledgments

### 11.1 — About Me

> **📌 Placeholder:** Replace with your real info.

- **Name:** `Tarek` 
- **Title:** `DevOps Engineer`

---

### 11.2 — Project Context

- Built as a **graduation project for iVolve Training**.
- Demonstrates a **complete CI/CD + GitOps pipeline** on AWS:
  - Terraform → Ansible → Jenkins → Docker + Trivy → ECR → Argo CD → EKS Fargate → ALB.
- Technologies exercised:
  - Terraform, Ansible, Jenkins, Docker, Trivy, ECR, EKS, Fargate, Kubernetes, Argo CD, AWS Load Balancer Controller, IAM/IRSA, SNS, CloudWatch.

---

### 11.3 — Acknowledgments

- **iVolve Training** — for the training program, mentorship, and project specification.
- **NTI (National Telecommunication Institute)** — if applicable, for academic support.
- Mentors, instructors, and peers who provided feedback and helped debug tricky AWS/Kubernetes issues.

---

### 11.4 — License

- This project is licensed under the terms of the license specified in the root `LICENSE` file (e.g. MIT).
- You are free to use, modify and distribute under those terms; see `LICENSE` for details.

---

