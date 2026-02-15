# CloudDevOpsProject

Graduation project: CI/CD with Jenkins, ArgoCD, Kubernetes (EKS), Terraform (AWS), and Ansible.

---

## Architecture Overview

```
                    ┌─────────────────────────────────────────────────────────────────┐
                    │                         AWS Cloud                                 │
                    │  ┌─────────────┐    ┌──────────────┐    ┌─────────────────────┐ │
                    │  │   VPC       │    │ Jenkins EC2  │    │ EKS (Fargate)        │ │
                    │  │ - Subnets   │───▶│ - SG 22,8080 │    │ - ArgoCD             │ │
                    │  │ - IGW       │    │ - Ansible    │    │ - App (ivolve-app)    │ │
                    │  │ - NACL      │    │   config     │    │ - ALB Ingress         │ │
                    │  └─────────────┘    └──────┬───────┘    └──────────▲──────────┘ │
                    │                             │                        │            │
                    │                      ┌──────┴───────┐         ┌──────┴──────┐    │
                    │                      │ CloudWatch   │         │ ECR         │    │
                    │                      │ + SNS Alerts │         │ (images)    │    │
                    │                      └──────────────┘         └──────▲──────┘    │
                    └─────────────────────────────────────────────────────│───────────┘
                                                                           │
  Developer ──▶ GitHub ──▶ Jenkins (Build → Scan → Push Image → Update/Push Manifests)
                                                                           │
                                    ArgoCD syncs from Git (k8s/) ──────────┘
```

- **Terraform**: Provisions VPC, public subnets, IGW, NACL, Jenkins EC2, security groups, EKS (Fargate), SNS, CloudWatch. State in HCP Terraform (Terraform Cloud).
- **Ansible**: Targets Jenkins EC2 (dynamic inventory by tag). Installs Git, Java, Docker, Jenkins, Trivy, kubectl; configures EKS access; installs Helm, ArgoCD, AWS LB Controller; applies ArgoCD Application.
- **Jenkins**: Pipeline (Jenkinsfile + Shared Library) builds image, scans (Trivy), pushes to ECR, updates `k8s/deployment.yaml`, pushes manifests to Git.
- **ArgoCD**: Syncs from this repo `k8s/` into EKS namespace `ivolve` (Deployment, Service, Ingress).

---

## Repository Structure

| Path | Purpose |
|------|--------|
| `docker/` | Dockerfile and app build context |
| `app-project/` | Application source (Python app) |
| `k8s/` | Kubernetes manifests (namespace, deployment, service, ingress) |
| `terraform/` | AWS infrastructure (VPC, EC2, EKS, SNS, CloudWatch) |
| `ansible/` | Playbook and roles (Jenkins, helm-install, alb-iam); dynamic inventory |
| `Shared-Library/` | Jenkins Shared Library (vars: buildImage, scanImage, pushImageECR, etc.) |
| `vars/` | Same library steps (deliverable: "Shared library directory (vars)") |
| `Jenkinsfile` | CI pipeline: Build → Scan → Push Image → Remove Local → Update Manifests → Push Manifests |
| `argocd/` | ArgoCD Application manifest |

---

## Setup Instructions

### Prerequisites

- AWS account; AWS CLI configured (or Terraform Cloud with AWS credentials).
- For Ansible: `ansible-core`, `boto3`, `botocore`; `pip install ansible boto3`.
- For Terraform: Terraform 1.x; HCP Terraform (Terraform Cloud) account for state.
- EC2 key pair in AWS (e.g. `jenkins_key`) in the same region as Terraform.

### 1. Terraform (Infrastructure)

- In HCP Terraform workspace, set env vars: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` (sensitive).
- Copy `terraform/terraform.tfvars.example` to `terraform/terraform.tfvars` and set `aws_account_id`, `jenkins_key_name`, `sns_alert_email`, etc. (do not commit tfvars.)
- From `terraform/`: `terraform init` then `terraform apply`.
- Note outputs: `jenkins_public_ip`, `eks_cluster_name`. Ensure ECR repository `ivolve-app` exists in the same account/region (create manually or via Terraform if desired).

### 2. Ansible (Configure Jenkins EC2)

- Ensure `ansible/main.yaml` vars match Terraform: `cluster_name` = EKS name, `aws_region`, `aws_account_id`.
- From repo root:  
  `ansible-playbook -i ansible/inventory/aws-ec2.yaml ansible/main.yaml`
- Requires AWS credentials (env or profile) so dynamic inventory can find the Jenkins EC2 (tag `service=jenkins`).

### 3. Jenkins

- Open Jenkins at `http://<jenkins_public_ip>:8080`, complete initial setup.
- Install plugins: Pipeline, Docker Pipeline, Git, (optional) AWS credentials / ECR.
- Configure Global Pipeline Library: name e.g. `ivolve-shared-library`, SCM = this repo, default version `main`; if library is in subfolder, set "Resource" / "Include" so `vars/` or `Shared-Library/` is the library root.
- Add credentials:  
  - AWS (for ECR push and, if used, ECR login in pipeline).  
  - Git (e.g. GitHub token or SSH key) for "Push Manifests" to this repo.
- Create Pipeline job: "Pipeline from SCM" → this repo, branch `main`, script path `Jenkinsfile`.

### 4. ArgoCD

- ArgoCD is installed by Ansible (helm-install) on EKS. Get URL (ingress or port-forward).
- In `argocd/application.yaml`, `repoURL` must point to this GitHub repo (e.g. `https://github.com/<org>/CloudDevOpsProject.git`). Adjust if your repo URL differs.
- ArgoCD will sync `k8s/` into namespace `ivolve`; CreateNamespace=true creates `ivolve` if needed.

### 5. Application Source

- Task required app source from `https://github.com/IbrahimAdel15/FinalProject.git`. The Dockerfile in this repo expects `app-project/` (Python app). Ensure `app-project/` is present and matches that source or a copy of it; Dockerfile is in `docker/` and is committed as required.

---

## Deliverables Checklist

| # | Deliverable | Status |
|---|-------------|--------|
| 1 | GitHub repo "CloudDevOpsProject" + README | ✅ Repo; README in this file |
| 2 | Dockerfile committed; app from FinalProject | ✅ `docker/Dockerfile`; ensure `app-project/` matches source |
| 3 | K8s cluster, ivolve namespace, Deployment, Service | ✅ `k8s/` (namespace, deployment, service, ingress) |
| 4 | Terraform: VPC, subnets, IGW, NACL, EC2 Jenkins, SG, CloudWatch, modules | ✅ State: HCP Terraform (as requested, not S3) |
| 5 | Ansible: packages (Git, Docker, Java), Jenkins, roles, dynamic inventory | ✅ `ansible/` |
| 6 | Jenkinsfile + Shared Library (vars): all 6 stages | ✅ `Jenkinsfile`; `Shared-Library/` and `vars/` |
| 7 | ArgoCD Application committed | ✅ `argocd/application.yaml` |
| 8 | Documentation: setup + architecture | ✅ This README |

---

## Notes

- **Terraform state**: Stored in HCP Terraform (Terraform Cloud), not S3, per project choice.
- **Shared Library**: Deliverable asks for "Shared library directory (vars)". This repo has both `Shared-Library/` and `vars/`; configure Jenkins to use one as the library root.
- **ArgoCD repo URL**: Update `argocd/application.yaml` if your GitHub org/user or repo name differs.
