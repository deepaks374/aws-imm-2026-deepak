# ==============================================================================
# CloudPulse Container Image Specification
# Designed with intentional CNAPP / CSPM / Image Scanner anti-patterns:
# 1. Obsolete / Vulnerable base image (python:3.8-slim with unpatched system packages)
# 2. Runs exclusively as root (UID 0) - violating least privilege
# 3. Excessive build tools installed (gcc, make, curl, net-tools, iputils-ping, nmap)
# 4. Insecure build-time package cache preservation
# 5. Build-time malware signature embedding (EICAR standard anti-virus test file)
# ==============================================================================

FROM python:3.8-slim

LABEL maintainer="cloudpulse-secops@enterprise-corp.io"
LABEL version="2.4.0"
LABEL tier="production-backend"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_ENV=production \
    APP_HOME=/opt/cloudpulse \
    DATA_STORE_PATH=/data/telemetry_vault.db \
    STORAGE_VAULT_MOUNT=/mnt/storage-vault

WORKDIR ${APP_HOME}

# Misconfiguration Vector: Running as root and installing unnecessary network/diagnostic tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    net-tools \
    iputils-ping \
    nmap \
    netcat-openbsd \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Malware Vector: Embedding standard EICAR test string in image layers for image scanner detection
# Validated by: Cortex Image Scanning, Prisma Cloud Defenses, ClamAV, Trivy
RUN echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /opt/cloudpulse/system_diagnostics.dat

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Ensure storage directories exist
RUN mkdir -p /data /mnt/storage-vault

EXPOSE 8080

# Insecure Container Posture: No USER directive provided (defaults to root)
CMD ["python", "app.py"]
