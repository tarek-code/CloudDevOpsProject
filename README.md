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

> **📌 Note:** Filenames below are examples. Rename them to match the actual files you added (for example under a `screenshots/` folder) so the images render correctly on GitHub.

| Jenkins Pipeline View | Argo CD Application Sync | Application Running via ALB |
| --------------------- | ------------------------ | --------------------------- |
| ![Jenkins Pipeline](screenshots/jenkins-pipeline.png) | ![Argo CD](screenshots/argocd-app.png) | ![App UI](screenshots/app-ui.png) |

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

![Terraform Apply](Screenshots/terraform-apply.png)

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

## CHAPTER 3 — The Application

This chapter describes the simple **Flask** application in `app-project/`:

- `app.py` — defines the Flask app, the `/` route, and runs on port 5000.
- `requirements.txt` — lists Python dependencies (currently just Flask).
- `templates/index.html` — the HTML page rendered at `/`.
- `static/style.css` — basic styling.

It shows how the application is structured, how Flask routes work, and how these files are copied and run inside the Docker container (see CHAPTER 4).

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

#### 5.x — What the Jenkins Pipeline Looks Like

1. Push code changes to GitHub (app, Dockerfile, or manifests).  
2. Jenkins automatically runs the pipeline: *Checkout → BuildImage → ScanImage → PushImage → UpdateManifests → PushManifests → Cleanup*.  
3. In the Jenkins UI, confirm that all stages are green and the build completed successfully.

![Jenkins Pipeline](Screenshots/jenkins-pipeline.png)

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

#### 6.x — Argo CD Showing the App in Sync

1. Open the Argo CD web UI and log in.  
2. Find the `ivolve-app` (or your app) in the **Applications** list.  
3. Confirm the status is **Healthy** and **Synced**, and drill into the tree view to see all Kubernetes resources.

![Argo CD Application](Screenshots/argocd-app.png)

---

## CHAPTER 7 — Kubernetes Manifests

This chapter walks through:

- `k8s/namespace.yaml` — creation of `ivolve` namespace.
- `k8s/deployment.yaml` — Deployment spec (replicas, pod template, container, probes, resources).
- `k8s/service.yaml` — ClusterIP service mapping port 80 → 5000.
- `k8s/ingress.yaml` — Ingress definition with ALB annotations (scheme, target-type, listen-ports, inbound-cidrs).

You’ll see how these manifests represent the final, desired state that Argo CD syncs to EKS.

---

#### 7.x — Pods Running on EKS Fargate

1. From a machine with kubeconfig (Jenkins EC2 or your laptop), run:

```bash
kubectl get pods -n ivolve
```

2. All pods should be in **Running** state, scheduled onto Fargate.  
3. If pods are pending, check IAM (IRSA), Fargate profiles, and namespace labels.

![EKS Pods](Screenshots/eks-pods.png)

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

| Jenkins Pipeline View | Argo CD Application Sync | Application Running via ALB |
| --------------------- | ------------------------ | --------------------------- |
| ![Jenkins Pipeline](screenshots/jenkins-pipeline.png) | ![Argo CD](screenshots/argocd-app.png) | ![App UI](screenshots/app-ui.png) |

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

