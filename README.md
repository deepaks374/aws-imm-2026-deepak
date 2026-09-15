# CloudPulse: Cortex CNAPP Code-to-Cloud Security Showcase

This repository provides an enterprise-grade demonstration of **Palo Alto Networks Cortex CNAPP (Cloud-Native Application Protection Platform)** capabilities across the full Code-to-Cloud lifecycle on AWS.

The environment showcases how Cortex delivers unified visibility, vulnerability management, posture enforcement, and active threat detection across **12 comprehensive attack vectors**, fully incorporating core OWASP Top 10 patterns adapted from **OWASP Juice Shop**:
1. **SQL Injection (SQLi)** ([`src/app.py:170`](src/app.py:170)) — Authentication bypass (' OR 1=1 --) & database exfiltration.
2. **NoSQL Injection (NoSQLi)** ([`src/app.py:218`](src/app.py:218)) — MongoDB-style operator filter injection (`$ne` / regex) inspired by Juice Shop's reviews.
3. **Broken Authentication & Session Management** ([`src/app.py:257`](src/app.py:257)) — Spoofed identity headers & unverified `none`-algorithm client tokens.
4. **Cross-Site Scripting (XSS) & Template Injection (SSTI)** ([`src/app.py:302`](src/app.py:302)) — Reflected payload injection into live rendered templates.
5. **Insecure Deserialization** ([`src/app.py:340`](src/app.py:340)) — Untrusted serialized object processing (Python pickle/YAML) enabling RCE.
6. **Server-Side Request Forgery (SSRF)** ([`src/app.py:371`](src/app.py:371)) — Arbitrary server webhook fetching targeted at AWS IMDS (`169.254.169.254`) and internal services.
7. **Broken Access Control (IDOR & Admin API Exposure)** ([`src/app.py:407`](src/app.py:407)) — Insecure Direct Object References to unowned customer records and unprotected administrative APIs.
8. **Security Misconfigurations & OS Command Injection** ([`src/app.py:442`](src/app.py:442)) — Leaked debug environment (`/api/v1/debug/env`) and shell execution via `/api/v1/diagnostics/ping`.
9. **Sensitive Data Exposure & DSPM** ([`src/app.py:485`](src/app.py:485)) — Unrestricted CSV export of unencrypted cardholder and PII records.
10. **Container Breakout & HostPath Escape (5 Techniques)** ([`scripts/simulate_attack.sh:267`](scripts/simulate_attack.sh:267)) — Host filesystem traversal, chroot breakout, persistence drop, raw block device mounting, and cgroup release agent.
11. **Fileless / In-Memory Crypto-Miner Execution** ([`scripts/simulate_attack.sh:449`](scripts/simulate_attack.sh:449)) — Disguised process execution (`.kworker_crypto`).
12. **Container Malware Drop** ([`scripts/simulate_attack.sh:485`](scripts/simulate_attack.sh:485)) — Runtime injection of standard anti-malware test signature (EICAR).

---

## Cortex Cloud Detection & Posture Vectors

### 1. Hardcoded Secrets & SAST Code Weaknesses ([`src/app.py:22`](src/app.py:22))
- **AWS API Keys**: High-entropy root access keys (`AKIAIOSFODNN7EXAMPLE`).
- **Payment Keys**: Live Stripe secret token (`sk_live_...`).
- **Developer & Third-Party Tokens**: GitHub Personal Access Tokens (`ghp_...`), Slack Incoming Webhooks, SendGrid API keys, and OpenAI keys.
- **Path Traversal & Arbitrary File Read**: ([`src/app.py:145`](src/app.py:145)) (`/api/v1/system/file-view`).
- **Insecure Cryptography & PRNG**: MD5 hash usage and predictable token generation (`insecure_generate_token`).

### 2. Infrastructure-as-Code (IaC) & Cloud Posture (CSPM) ([`infra/insecure_posture_assets.tf:1`](infra/insecure_posture_assets.tf:1))
- **Unencrypted S3 Bucket with Public Access**: `aws_s3_bucket.unencrypted_public_logs` with all public access blocks disabled.
- **Unrestricted Security Groups**: `aws_security_group.overly_permissive_ingress` allowing `0.0.0.0/0` access to Port 22 (SSH), Port 5432 (PostgreSQL), and Port 3389 (RDP).
- **Unencrypted Storage**: `aws_ebs_volume.unencrypted_diagnostic_volume` without KMS encryption enabled.
- **EC2 IMDSv1 Misconfiguration**: Launch template with `http_tokens = "optional"` permitting SSRF credential scraping.

### 3. Identity & Entitlement Risk (CIEM) ([`infra/main.tf:371`](infra/main.tf:371) & [`infra/insecure_posture_assets.tf:95`](infra/insecure_posture_assets.tf:95))
- **Wildcard Admin IAM Role**: Overprivileged cross-account assume role with `Resource = "*"` and `Action = ["s3:*", "iam:PassRole", "ec2:*"]`.
- **Legacy Machine User**: `aws_iam_user.legacy_service_operator` with administrator permissions and static unrotated access keys.

### 4. Kubernetes Security Posture Management (KSPM) ([`k8s/insecure_k8s_misconfigs.yaml:1`](k8s/insecure_k8s_misconfigs.yaml:1))
- **Pod Namespace Sharing**: `hostNetwork: true`, `hostIPC: true`, `hostPID: true`.
- **Docker Socket Mount**: Direct volume mount of `/var/run/docker.sock`.
- **Privileged Context**: `privileged: true`, `capabilities: [ALL]`, and `runAsUser: 0`.

---

## The 3-Step Execution Workflow

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

---

### Step 2: CI/CD Pipeline & Deployment

The CI/CD pipeline in [`.github/workflows/code-to-cloud.yml`](.github/workflows/code-to-cloud.yml:1) automatically builds the container image from source, runs pytest unit verification, scans image layers, pushes it to Amazon ECR, and applies the Kubernetes manifests to EKS.

---

### Step 3: Runtime Attack Simulation

Run the interactive attack simulation suite:

```bash
./scripts/simulate_attack.sh
```

Or execute via non-interactive CLI:
- Run all attacks: `./scripts/simulate_attack.sh --all`
- Run container escape suite: `./scripts/simulate_attack.sh --escape`
- Run specific attack: `./scripts/simulate_attack.sh --attack sqli` (or `nosqli`, `auth`, `xss`, `deserialization`, `ssrf`, `idor`, `misconfig`, `dspm`, `escape`, `fileless`, `malware`)
