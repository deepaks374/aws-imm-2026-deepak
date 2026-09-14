# CloudPulse: Cortex CNAPP Code-to-Cloud Security Showcase

This repository provides an enterprise-grade demonstration of **Palo Alto Networks Cortex CNAPP (Cloud-Native Application Protection Platform)** capabilities across the full Code-to-Cloud lifecycle on AWS.

The environment showcases how Cortex delivers unified visibility, vulnerability management, posture enforcement, and active threat detection across **12 comprehensive attack vectors**, fully incorporating core OWASP Top 10 patterns adapted from **OWASP Juice Shop**:
1. **SQL Injection (SQLi)** ([`src/app.py:127`](src/app.py:127)) — Authentication bypass (' OR 1=1 --) & database exfiltration.
2. **NoSQL Injection (NoSQLi)** ([`src/app.py:175`](src/app.py:175)) — MongoDB-style operator filter injection (`$ne` / regex) inspired by Juice Shop's reviews.
3. **Broken Authentication & Session Management** ([`src/app.py:214`](src/app.py:214)) — Spoofed identity headers & unverified `none`-algorithm client tokens.
4. **Cross-Site Scripting (XSS) & Template Injection (SSTI)** ([`src/app.py:259`](src/app.py:259)) — Reflected payload injection into live rendered templates.
5. **Insecure Deserialization** ([`src/app.py:297`](src/app.py:297)) — Untrusted serialized object processing (Python pickle/YAML) enabling RCE.
6. **Server-Side Request Forgery (SSRF)** ([`src/app.py:328`](src/app.py:328)) — Arbitrary server webhook fetching targeted at AWS IMDS (`169.254.169.254`) and internal services.
7. **Broken Access Control (IDOR & Admin API Exposure)** ([`src/app.py:364`](src/app.py:364)) — Insecure Direct Object References to unowned customer records and unprotected administrative APIs.
8. **Security Misconfigurations & OS Command Injection** ([`src/app.py:399`](src/app.py:399)) — Leaked debug environment (`/api/v1/debug/env`) and shell execution via `/api/v1/diagnostics/ping`.
9. **Sensitive Data Exposure & DSPM** ([`src/app.py:442`](src/app.py:442)) — Unrestricted CSV export of unencrypted cardholder and PII records.
10. **Container Breakout & HostPath Escape** ([`scripts/simulate_attack.sh:267`](scripts/simulate_attack.sh:267)) — Host filesystem traversal (`/host-node-root`) and process namespace breakout.
11. **Fileless / In-Memory Crypto-Miner Execution** ([`scripts/simulate_attack.sh:301`](scripts/simulate_attack.sh:301)) — Disguised process execution (`.kworker_crypto`).
12. **Container Malware Drop** ([`scripts/simulate_attack.sh:337`](scripts/simulate_attack.sh:337)) — Runtime injection of standard anti-malware test signature (EICAR).

---

## The 3-Step Execution Workflow

The demonstration is organized so that you only need to execute **three manual steps**:

```
┌─────────────────────────────────┐
│ Step 1: Provision Infrastructure │  ──>  cd infra && terraform apply
└─────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│ Step 2: CI/CD Pipeline & Deploy  │  ──>  git push origin main (triggers GitHub Actions)
└─────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│ Step 3: Runtime Attack Sim      │  ──>  ./scripts/simulate_attack.sh
└─────────────────────────────────┘
```

---

### Step 1: Infrastructure Provisioning

Navigate to the [`infra/`](infra/:1) directory and apply the Terraform configuration:

```bash
cd infra
terraform init
terraform apply -auto-approve
```

#### What Gets Provisioned:
* **VPC Architecture**: Dedicated VPC (`10.120.0.0/16`) with multi-AZ public and private subnets, NAT Gateway, and routing tables.
* **Amazon EKS Cluster (v1.32)**: Managed Kubernetes control plane and worker node group with node pools sized for production telemetry.
* **Amazon ECR**: Container repository `cloudpulse-telemetry-engine` with automated scan-on-push.
* **Cluster & CI/CD Prerequisites**:
  * IAM OIDC Provider for EKS ServiceAccounts (IRSA) defined in [`infra/cortex_prereqs.tf:16`](infra/cortex_prereqs.tf:16).
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

The CI/CD pipeline in [`.github/workflows/code-to-cloud.yml`](.github/workflows/code-to-cloud.yml:1) automatically builds the container image from source, scans the image layers, pushes it to your Amazon ECR repository, and directly applies the Kubernetes manifests to the Amazon EKS cluster via `kubectl`.

#### Automated Pipeline Stages:
1. **01. Application Unit Testing**: Runs [`src/test_app.py:1`](src/test_app.py:1) to test all OWASP vulnerability endpoints and verify application integrity before containerization.
2. **02. CNAPP Source & IaC Security Scan**:
   * **SAST & Secrets**: Scans [`src/app.py:17`](src/app.py:17) for hardcoded AWS keys, Stripe tokens, SQLi, SSTI, and OS command injection flaws.
   * **IaC Posture**: Audits Terraform files in [`infra/main.tf:1`](infra/main.tf:1) and K8s manifests in [`k8s/deployment.yaml:1`](k8s/deployment.yaml:1) for privileged mode, IMDSv1 allowance, and hostPath mounts.
3. **03. Container Build, Scan & ECR Push**:
   * Builds the Docker image based on [`src/Dockerfile:10`](src/Dockerfile:10).
   * Identifies unpatched base image packages, root execution, and the embedded **EICAR anti-malware test signature** in layer `/opt/cloudpulse/system_diagnostics.dat`.
   * Authenticates to AWS via OIDC and pushes both `:${{ github.sha }}` and `:latest` tags directly to your Amazon ECR repository.
4. **04. Deploy Directly to EKS Cluster**:
   * Updates `kubeconfig` for cluster `cloudpulse-cnapp-eks` in `ap-south-1`.
   * Dynamically injects the newly built ECR image tag into [`k8s/deployment.yaml:36`](k8s/deployment.yaml:36).
   * Applies [`k8s/service.yaml:1`](k8s/service.yaml:1) and [`k8s/deployment.yaml:1`](k8s/deployment.yaml:1) directly to EKS.
   * Waits for the deployment rollout to complete and verifies live pod status.

---

### Step 3: Runtime Attack Simulation

Once the pod is running in EKS, execute the interactive attack simulation script [`scripts/simulate_attack.sh:1`](scripts/simulate_attack.sh:1):

```bash
./scripts/simulate_attack.sh
```

You will be presented with an interactive menu:

```text
==================================================================
   CloudPulse CNAPP & OWASP Runtime Attack Simulation Suite      
   Target Environment: AWS EKS / Namespace: cloudpulse-core        
==================================================================

Select Attack Simulation Option:
 1) SQL Injection (SQLi) - Auth Bypass & DB Dump
 2) NoSQL Injection (NoSQLi) - Operator Filter Bypass
 3) Broken Authentication - Spoofed Identity & None-Alg JWT
 4) Cross-Site Scripting (XSS) & Template Injection (SSTI)
 5) Insecure Deserialization - Object Payload Processing
 6) Server-Side Request Forgery (SSRF) - IMDS & Cluster Svc
 7) Broken Access Control - IDOR & Admin User Enumeration
 8) Security Misconfigurations - Debug Environment & Shell RCE
 9) Sensitive Data Exposure & DSPM Vault Exfiltration
 10) Host Escape & HostPath Misconfiguration Breakout
 11) Fileless / In-Memory Crypto-Miner Execution
 12) Container Malware Drop (/tmp EICAR Artifact)
 13) Execute ALL Attack Simulations Sequentially
 0) Exit
```

#### Non-Interactive CLI Usage:
* Run all attacks: `./scripts/simulate_attack.sh --all`
* Run a specific attack: `./scripts/simulate_attack.sh --attack sqli` (or `nosqli`, `auth`, `xss`, `deserialization`, `ssrf`, `idor`, `misconfig`, `dspm`, `escape`, `fileless`, `malware`)

---

## CNAPP & OWASP Coverage Matrix

| Vector | File Reference | Cortex CNAPP Module | Expected Alert / Protection Behavior |
|---|---|---|---|
| **SQL Injection (SQLi)** | [`src/app.py:127`](src/app.py:127) | Cortex Web & API / Code Security | Flags SQL string concatenation and detects SQL injection auth bypass attempts. |
| **NoSQL Injection (NoSQLi)** | [`src/app.py:175`](src/app.py:175) | Cortex Web & API Security | Detects unauthorized query operators (`$ne`, `$regex`) dumping document collections. |
| **Broken Authentication** | [`src/app.py:214`](src/app.py:214) | Cortex Identity & ITDR | Detects unsigned JWT tokens and spoofable identity header impersonation. |
| **XSS & SSTI** | [`src/app.py:259`](src/app.py:259) | Cortex Web & API / Code Security | Intercepts reflected script payloads and unescaped Jinja2 server template rendering. |
| **Insecure Deserialization** | [`src/app.py:297`](src/app.py:297) | Cortex Runtime & Code Security | Flags untrusted byte unpickling and blocks unauthorized process execution. |
| **Server-Side Request Forgery (SSRF)** | [`src/app.py:328`](src/app.py:328) | Cortex Network & Cloud Guardrails | Blocks unauthorized server HTTP requests to AWS IMDS (`169.254.169.254`). |
| **Broken Access Control (IDOR)** | [`src/app.py:364`](src/app.py:364) | Cortex API Security | Alerts on horizontal access violations and unauthorized admin API endpoint discovery. |
| **Security Misconfiguration & RCE** | [`src/app.py:399`](src/app.py:399) | Cortex Runtime Workload Protection | Flags unescaped system shell execution (`ping -c 2`) and debug variable leakage. |
| **Sensitive Data Exposure / DSPM** | [`src/app.py:442`](src/app.py:442) | Cortex DSPM Data Security | Discovers unencrypted PCI-DSS cardholder records and PII in storage mounts and S3. |
| **Container Breakout** | [`scripts/simulate_attack.sh:267`](scripts/simulate_attack.sh:267) | Cortex Container Security | Alerts on hostPath traversal to `/etc/shadow` and namespace escape via `nsenter`. |
| **Fileless Cryptominer** | [`scripts/simulate_attack.sh:301`](scripts/simulate_attack.sh:301) | Cortex Behavioral Analytics | Detects masqueraded mining processes launched in memory (`.kworker_crypto`). |
| **Container Malware Drop** | [`scripts/simulate_attack.sh:337`](scripts/simulate_attack.sh:337) | Cortex Runtime Anti-Malware | Triggers instant real-time malware detection on EICAR test signature drop in `/tmp`. |

---

## Directory Layout

```text
aws-imm-2026-deepak/
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
│   └── simulate_attack.sh          # Interactive 12-vector attack simulation suite (OWASP + CNAPP)
├── src/                            # Application source
│   ├── app.py                      # Flask service with OWASP Top 10 vulnerabilities & DSPM endpoints
│   ├── Dockerfile                  # Insecure container specification with embedded EICAR
│   ├── requirements.txt            # Python dependencies
│   └── test_app.py                 # Pytest unit tests for all OWASP endpoints (CI/CD stage 1)
└── README.md                       # 3-step execution guide & CNAPP/OWASP matrix
```
