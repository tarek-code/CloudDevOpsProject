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
| `Shared-Library/` | Jenkins Shared Library (buildImage, scanImage, pushImageECR, etc.); Ansible configures Jenkins to use it via JCasC |
| `Jenkinsfile` | CI pipeline: Build → Scan → Push Image → Remove Local → Update Manifests → Push Manifests |
| `argocd/` | ArgoCD Application manifest |

---

## Setup Instructions

### Prerequisites

- AWS account; AWS CLI configured (or Terraform Cloud with AWS credentials).
- For Ansible: `ansible-core`, `boto3`, `botocore`; `pip install ansible boto3`. Then install the AWS collection for dynamic inventory and alb-iam role: `ansible-galaxy collection install -r ansible/requirements.yml`.
- For Terraform: Terraform 1.x; HCP Terraform (Terraform Cloud) account for state.
- EC2 key pair in AWS (e.g. `jenkins_key`) in the same region as Terraform.

### 1. Terraform (Infrastructure)

- In HCP Terraform workspace, set env vars: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` (sensitive).
- Copy `terraform/terraform.tfvars.example` to `terraform/terraform.tfvars` and set `aws_account_id`, `jenkins_key_name`, `sns_alert_email`, etc. (do not commit tfvars.)
- From `terraform/`: `terraform init` then `terraform apply`.
- Note outputs: `jenkins_public_ip`, `eks_cluster_name`. ECR repository `ivolve-app` is created by Terraform so the Jenkins pipeline can push the image without errors.

### 2. Ansible (Configure Jenkins EC2)

- Ensure `ansible/main.yaml` vars match Terraform: `cluster_name` = EKS name, `aws_region`, `aws_account_id`.
- From repo root (no GitHub credential):  
  `ansible-playbook -i ansible/inventory/aws-ec2.yaml ansible/main.yaml`
- **GitHub username and token passed by Ansible to Jenkins (no manual Jenkins config):**  
  Run the playbook with your GitHub username and token; Ansible will inject them into Jenkins via JCasC so the pipeline can push to Git. One command:
  ```bash
  ansible-playbook -i ansible/inventory/aws-ec2.yaml ansible/main.yaml \
    -e jenkins_github_username=YOUR_GITHUB_USERNAME \
    -e jenkins_github_token=YOUR_GITHUB_PAT
  ```
  Replace `YOUR_GITHUB_USERNAME` and `YOUR_GITHUB_PAT` (e.g. a classic token with `repo` scope). You do not add any credential in the Jenkins UI—Ansible does it.
- **Optional (more secure):** Put username/token in an encrypted vault file so they are not on the command line. See `ansible/group_vars/all/vault.yml.example` if present; then run with `--ask-vault-pass`.
- Requires AWS credentials (env or profile) so dynamic inventory can find the Jenkins EC2 (tag `service=jenkins`).

### 3. Permissions (ECR + GitHub)

- **ECR:** The Jenkins EC2 instance has an **IAM instance profile** (Terraform) with permissions for ECR and EKS. No AWS keys in Jenkins; the instance uses the role automatically.
- **GitHub:** Ansible passes your **username** and **token** into Jenkins (JCasC). You do not configure anything in Jenkins yourself; run the playbook with `-e jenkins_github_username=... -e jenkins_github_token=...` (or vault) and the credential is created for the pipeline.

### 4. Jenkins

- Open Jenkins at `http://<jenkins_public_ip>:8080`, complete initial setup.
- Install plugins: Pipeline, Docker Pipeline, Git. AWS credentials are not required on Jenkins for ECR (instance profile is used).
- **Ansible configures Jenkins to see the Shared Library:** The Jenkins role deploys the Configuration as Code (JCasC) plugin and a `casc.yaml` that defines the Global Pipeline Library (name `ivolve-shared-library`, repo = this repo, branch `main`). So after you run the Ansible playbook, Jenkins automatically has the Shared Library—no manual "Manage Jenkins → Global Pipeline Libraries" setup. When you also pass `jenkins_github_username` and `jenkins_github_token` (via `-e` or vault), Ansible adds the GitHub credential in Jenkins for Push Manifests.
- Create Pipeline job: "Pipeline from SCM" → this repo, branch `main`, script path `Jenkinsfile`.

### 5. ArgoCD

- ArgoCD is installed by Ansible (helm-install) on EKS. Get URL (ingress or port-forward).
- In `argocd/application.yaml`, `repoURL` must point to this GitHub repo (e.g. `https://github.com/<org>/CloudDevOpsProject.git`). Adjust if your repo URL differs.
- ArgoCD will sync `k8s/` into namespace `ivolve`; CreateNamespace=true creates `ivolve` if needed.

### 6. Application Source

- Task required app source from `https://github.com/IbrahimAdel15/FinalProject.git`. The Dockerfile in this repo expects `app-project/` (Python app). Ensure `app-project/` is present and matches that source or a copy of it; Dockerfile is in `docker/` and is committed as required.

---

## Deliverables Checklist

| # | Deliverable | Status |
|---|-------------|--------|
| 1 | GitHub repo "CloudDevOpsProject" + README | ✅ Repo; README in this file |
| 2 | Dockerfile committed; app from FinalProject | ✅ `docker/Dockerfile`; `app-project/` from that source |
| 3 | K8s cluster, ivolve namespace, Deployment, Service | ✅ `k8s/` (namespace, deployment, service, ingress) |
| 4 | Terraform: VPC, subnets, IGW, NACL, EC2 Jenkins, SG, CloudWatch, modules | ✅ Terraform in `terraform/`; state in **HCP Terraform** (Hashicorp) |
| 5 | Ansible: packages (Git, Docker, Java), Jenkins, roles, dynamic inventory | ✅ `ansible/` (roles, playbook, dynamic inventory) |
| 6 | Jenkinsfile + Shared Library (vars): all 6 stages | ✅ `Jenkinsfile`; `Shared-Library/` (steps); Ansible configures Jenkins to use it via JCasC |
| 7 | ArgoCD Application committed | ✅ `argocd/application.yaml` |
| 8 | Documentation: setup + architecture | ✅ This README (setup instructions + architecture overview) |

---

## Run Without Errors

- **Terraform:** Uses HCP Terraform (Hashicorp) for state; no S3 backend. ECR repository `ivolve-app` is created by Terraform so the first Jenkins pipeline push does not fail.
- **Ansible:** Configures Jenkins (Shared Library + optional GitHub credential) so you do not configure the library or Git credential manually.
- **Jenkins:** After Ansible runs, Jenkins sees the Shared Library from this repo; run the playbook with `-e jenkins_github_username=... -e jenkins_github_token=...` so Push Manifests can push to Git.

---

## Notes

- **Terraform state**: Stored in HCP Terraform (Hashicorp), per project choice.
- **Shared Library**: Ansible configures Jenkins (JCasC) with `libraryPath: "Shared-Library"` so Jenkins uses your `Shared-Library/` folder. Put your step scripts in `Shared-Library/vars/` (e.g. `Shared-Library/vars/buildImage.groovy`) so Jenkins finds them—move the existing `.groovy` files from `Shared-Library/` into `Shared-Library/vars/`.
- **ArgoCD repo URL**: Update `argocd/application.yaml` if your GitHub org/user or repo name differs.
