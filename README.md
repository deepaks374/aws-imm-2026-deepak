# CloudPulse: Cortex CNAPP Code-to-Cloud Security Showcase

This repository provides an enterprise-grade demonstration of **Palo Alto Networks Cortex CNAPP (Cloud-Native Application Protection Platform)** capabilities across the full Code-to-Cloud lifecycle on AWS.

The environment showcases how Cortex delivers unified visibility, vulnerability management, posture enforcement, and active threat detection across six core vectors:
1. **Malicious Code / SAST & Secret Leakage** ([`final-code/src/app.py:17`](final-code/src/app.py:17))
2. **Infrastructure-as-Code & K8s Misconfigurations** ([`final-code/infra/main.tf:225`](final-code/infra/main.tf:225) & [`final-code/k8s/deployment.yaml:49`](final-code/k8s/deployment.yaml:49))
3. **Container Image Vulnerabilities & Malware Embedding** ([`final-code/src/Dockerfile:35`](final-code/src/Dockerfile:35))
4. **Active Kubernetes Runtime Threats & Container Breakout** ([`final-code/scripts/simulate_attack.sh:65`](final-code/scripts/simulate_attack.sh:65))
5. **Cloud Infrastructure Entitlement Management (CIEM) & Identity Risk** ([`final-code/infra/main.tf:290`](final-code/infra/main.tf:290) & [`final-code/k8s/service.yaml:18`](final-code/k8s/service.yaml:18))
6. **Data Security Posture Management (DSPM) & Sensitive Asset Exposure** ([`final-code/infra/main.tf:260`](final-code/infra/main.tf:260) & [`final-code/src/app.py:108`](final-code/src/app.py:108))

---

## The 3-Step Execution Workflow

The demonstration is organized so that you only need to execute **three manual steps**:

```
┌─────────────────────────────────┐
│ Step 1: Provision Infrastructure │  ──>  cd final-code/infra && terraform apply
└─────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│ Step 2: CI/CD Pipeline & Deploy  │  ──>  git push origin main (triggers GitHub Actions)
└─────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│ Step 3: Runtime Attack Sim      │  ──>  ./final-code/scripts/simulate_attack.sh
└─────────────────────────────────┘
```

---

### Step 1: Infrastructure Provisioning

Navigate to the [`final-code/infra/`](final-code/infra/) directory and apply the Terraform configuration:

```bash
cd final-code/infra
terraform init
terraform apply -auto-approve
```

#### What Gets Provisioned:
* **VPC Architecture**: Dedicated VPC (`10.120.0.0/16`) with multi-AZ public and private subnets, NAT Gateway, and routing tables.
* **Amazon EKS Cluster (v1.32)**: Managed Kubernetes control plane and worker node group with node pools sized for production telemetry.
* **Amazon ECR**: Container repository `cloudpulse-telemetry-engine` with automated scan-on-push.
* **Cluster & CI/CD Prerequisites**:
  * IAM OIDC Provider for EKS ServiceAccounts (IRSA) defined in [`final-code/infra/cortex_prereqs.tf:16`](final-code/infra/cortex_prereqs.tf:16).
  * GitHub Actions OIDC provider and deployer role (`cloudpulse-cnapp-eks-github-deployer-role`).
* **CIEM & DSPM Assets**:
  * Overprivileged IAM role with wildcard permissions (`CloudPulse-CloudOps-OverprivilegedServiceRole`).
  * S3 Bucket (`cloudpulse-restricted-data-vault-*`) with synthetic PCI-DSS and PII data records for DSPM discovery.

Configure your local `kubectl` using the Terraform output:
```bash
aws eks --region ap-south-1 update-kubeconfig --name cloudpulse-cnapp-eks
```

---

### Step 2: CI/CD Pipeline & Deployment

The CI/CD pipeline in [`.github/workflows/code-to-cloud.yml`](final-code/.github/workflows/code-to-cloud.yml:1) automatically builds the container image from source, scans the image layers, pushes it to your Amazon ECR repository, and directly applies the Kubernetes manifests to the Amazon EKS cluster via `kubectl`.

#### Prerequisites for GitHub Actions:
In your GitHub repository, navigate to **Settings > Secrets and variables > Actions**, and configure the following secrets:
1. **`AWS_DEPLOY_ROLE_ARN`**: The IAM Role ARN output from Terraform (Step 1).
2. **`CORTEX_API_KEY`**: Your Palo Alto Networks Cortex API Key token.
3. **`CORTEX_API_KEY_ID`**: Your Palo Alto Networks Cortex API Key ID.

#### Triggering the Pipeline:
Push code changes to the `main` branch (or run via GitHub Actions **Run workflow** dispatch):

```bash
git add .
git commit -m "feat: build image, push to ECR, and deploy to EKS"
git push origin main
```

#### Automated Pipeline Stages:
1. **01. Application Unit Testing**: Runs [`final-code/src/test_app.py:1`](final-code/src/test_app.py:1) to ensure software quality before containerization.
2. **02. CNAPP Source & IaC Security Scan**:
   * **SAST & Secrets**: Scans [`final-code/src/app.py:17`](final-code/src/app.py:17) for hardcoded AWS keys, Stripe tokens, and SQL/Command injection flaws.
   * **IaC Posture**: Audits Terraform files in [`final-code/infra/main.tf:1`](final-code/infra/main.tf:1) and K8s manifests in [`final-code/k8s/deployment.yaml:1`](final-code/k8s/deployment.yaml:1) for privileged mode, IMDSv1 allowance, and hostPath mounts.
3. **03. Container Build, Scan & ECR Push**:
   * Builds the Docker image based on [`final-code/src/Dockerfile:10`](final-code/src/Dockerfile:10).
   * Identifies unpatched base image packages, root execution, and the embedded **EICAR anti-malware test signature** in layer `/opt/cloudpulse/system_diagnostics.dat`.
   * Authenticates to AWS via OIDC and pushes both `:${{ github.sha }}` and `:latest` tags directly to your Amazon ECR repository.
4. **04. Deploy Directly to EKS Cluster**:
   * Updates `kubeconfig` for cluster `cloudpulse-cnapp-eks` in `ap-south-1`.
   * Dynamically injects the newly built ECR image tag into [`final-code/k8s/deployment.yaml:39`](final-code/k8s/deployment.yaml:39).
   * Applies [`final-code/k8s/service.yaml:1`](final-code/k8s/service.yaml:1) and [`final-code/k8s/deployment.yaml:1`](final-code/k8s/deployment.yaml:1) directly to EKS.
   * Waits for the deployment rollout to complete and verifies live pod status.

---

### Step 3: Runtime Attack Simulation

Once the pod is running in EKS, execute the interactive attack simulation script [`final-code/scripts/simulate_attack.sh:1`](final-code/scripts/simulate_attack.sh:1):

```bash
./final-code/scripts/simulate_attack.sh
```

You will be presented with an interactive menu:

```text
==================================================================
   Cortex CNAPP & Kubernetes Runtime Attack Simulation Suite     
   Target Environment: AWS EKS / Namespace: cloudpulse-core        
==================================================================

Select Attack Simulation Option:
 1) Malware Drop (/tmp EICAR payload)
 2) Fileless / In-Memory Crypto-Miner Execution
 3) Host Escape & HostPath Misconfiguration Exploit
 4) Lateral Movement & Internal Service Probing
 5) CIEM / Cloud & K8s Credential Scraping (IMDS & ServiceAccount)
 6) DSPM Sensitive Data Access & Exposure
 7) Execute All Attack Simulations Sequentially
 0) Exit
```

#### Non-Interactive CLI Usage:
* Run all attacks: `./final-code/scripts/simulate_attack.sh --all`
* Run a specific attack: `./final-code/scripts/simulate_attack.sh --attack 3`

---

## CNAPP Coverage Matrix & Demonstration Vectors

| Vector | File Reference | Cortex CNAPP Module | Expected Alert / Protection Behavior |
|---|---|---|---|
| **SAST & Secrets** | [`final-code/src/app.py:17`](final-code/src/app.py:17) | Cortex Code Security | Alerts on hardcoded AWS keys, Stripe tokens, SQLi, and OS command injection. |
| **IaC Misconfig** | [`final-code/infra/main.tf:225`](final-code/infra/main.tf:225) | Cortex Cloud Posture (CSPM) | Identifies EC2 IMDSv1 optional tokens and unencrypted S3 bucket public access. |
| **K8s Misconfig** | [`final-code/k8s/deployment.yaml:49`](final-code/k8s/deployment.yaml:49) | Cortex KSPM / Admission | Flags `privileged: true`, `hostPID: true`, `hostPath: /`, and missing resource limits. |
| **Container Malware** | [`final-code/src/Dockerfile:35`](final-code/src/Dockerfile:35) | Cortex Image Security | Detects embedded EICAR signature and flags root-user container image build. |
| **Runtime Malware** | [`final-code/scripts/simulate_attack.sh:65`](final-code/scripts/simulate_attack.sh:65) | Cortex Runtime Anti-Malware | Triggers real-time file-write and execution alert for `/tmp/system_upgrade.bin`. |
| **Fileless Process** | [`final-code/scripts/simulate_attack.sh:90`](final-code/scripts/simulate_attack.sh:90) | Cortex Behavioral Analytics | Detects masqueraded cryptominer process launching from `/tmp/.kworker_crypto`. |
| **Container Breakout** | [`final-code/scripts/simulate_attack.sh:125`](final-code/scripts/simulate_attack.sh:125) | Cortex Workload Protection | Alerts on container breakout via `hostPath` access to `/etc/shadow` and `nsenter`. |
| **Lateral Movement** | [`final-code/scripts/simulate_attack.sh:155`](final-code/scripts/simulate_attack.sh:155) | Cortex Network Security | Flags suspicious cross-namespace probing against `ledger-backend-service`. |
| **CIEM & Cloud Keys** | [`final-code/scripts/simulate_attack.sh:185`](final-code/scripts/simulate_attack.sh:185) | Cortex CIEM & ITDR | Flags overprivileged `cluster-admin` ServiceAccount token scraping & IMDS extraction. |
| **DSPM Data Risk** | [`final-code/scripts/simulate_attack.sh:215`](final-code/scripts/simulate_attack.sh:215) | Cortex DSPM Data Security | Discovers unencrypted cardholder and PII records in storage volume and S3 bucket. |

---

## Directory Layout

```text
final-code/
├── .github/
│   └── workflows/
│       └── code-to-cloud.yml       # 4-stage CI/CD security pipeline
├── infra/                          # Terraform infrastructure
│   ├── main.tf                     # EKS (v1.32), VPC, ECR, S3 DSPM vault, CIEM IAM role
│   ├── cortex_prereqs.tf           # OIDC, Cortex Agent IAM roles & IRSA bindings
│   └── outputs.tf                  # Outputs (ECR URL, EKS endpoint, kubeconfig command)
├── k8s/                            # Kubernetes manifests
│   ├── deployment.yaml             # Workload deployment with privileged & hostPath anti-patterns
│   └── service.yaml                # Core namespace, service, overprivileged RBAC, and target DB
├── scripts/
│   └── simulate_attack.sh          # Interactive 6-vector attack simulation script
├── src/                            # Application source
│   ├── app.py                      # Flask service with SAST/RCE/SQLi and DSPM endpoints
│   ├── Dockerfile                  # Insecure container specification with embedded EICAR
│   ├── requirements.txt            # Python dependencies
│   └── test_app.py                 # Pytest unit tests for CI/CD stage 1
└── README.md                       # 3-step execution guide & CNAPP matrix
```
