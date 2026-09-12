"""
CloudPulse Analytics Engine - Telemetry Ingestion and Data Processing Gateway.
Enterprise microservice demonstrating cloud-native application flows with intentional
security anti-patterns for CNAPP SAST, secret, and runtime posture validation.
"""

import os
import sqlite3
import subprocess
import logging
from flask import Flask, request, jsonify

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# ==============================================================================
# SAST Vector 1: Hardcoded High-Entropy Secrets & API Keys
# Detected by: Cortex Code Security (Secret Scanning & SAST)
# ==============================================================================
PRIMARY_AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
PRIMARY_AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
STRIPE_INTEGRATION_LIVE_KEY = "sk_live_51Mz000CloudPulse999EnterpriseSecretKeyToken"
DATABASE_ADMIN_CONNECTION_URI = "postgres://telemetry_admin:SuperSecretAdminPassw0rd2026!@telemetry-rds.internal.net:5432/cloudpulse_prod"

import tempfile

DEFAULT_DATA_DIR = os.environ.get("DATA_STORE_DIR", tempfile.gettempdir())
DATA_STORE_PATH = os.environ.get("DATA_STORE_PATH", os.path.join(DEFAULT_DATA_DIR, "telemetry_vault.db"))
STORAGE_VAULT_MOUNT = os.environ.get("STORAGE_VAULT_MOUNT", os.path.join(DEFAULT_DATA_DIR, "storage-vault"))


def initialize_storage_vault():
    """Initializes local storage cache with synthetic PII/financial data for DSPM."""
    os.makedirs(os.path.dirname(DATA_STORE_PATH), exist_ok=True)
    os.makedirs(STORAGE_VAULT_MOUNT, exist_ok=True)

    # Seed synthetic DSPM test data in storage mount (credit cards, PII, SSNs)
    sample_pii_file = os.path.join(STORAGE_VAULT_MOUNT, "customer_billing_records.csv")
    if not os.path.exists(sample_pii_file):
        with open(sample_pii_file, "w") as f:
            f.write("customer_id,full_name,email,tax_id_ssn,primary_card_number,cvv\n")
            f.write("CP-1001,Johnathan Vance,jvance@enterprise-client.com,987-65-4321,4532-8901-2345-6789,882\n")
            f.write("CP-1002,Elena Rostova,erostova@fin-corp.global,321-54-9870,5424-1800-4321-9876,143\n")
            f.write("CP-1003,Marcus Sterling,msterling@apex-partners.io,456-78-1234,3782-822463-10005,509\n")

    conn = sqlite3.connect(DATA_STORE_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS system_telemetry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_identifier TEXT,
            metric_category TEXT,
            raw_payload TEXT,
            recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


@app.route("/", methods=["GET"])
def health_status():
    """Standard health probe endpoint."""
    return jsonify({
        "service": "cloudpulse-telemetry-engine",
        "status": "operational",
        "version": "2.4.0",
        "environment": os.environ.get("APP_ENV", "production")
    }), 200


@app.route("/api/v1/diagnostics/ping", methods=["POST"])
def network_diagnostics():
    """
    SAST Vector 2: Remote Code Execution / Command Injection.
    Vulnerability: Unsanitized user input passed directly to system shell.
    Detected by: Cortex Code Security & Cortex K8s Runtime Agent (process spawn).
    """
    data = request.get_json(silent=True) or {}
    target_host = data.get("target_host", "127.0.0.1")

    # Intentional Command Injection vulnerability (shell=True with formatted input)
    command = f"ping -c 2 {target_host}"
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True, timeout=5)
        return jsonify({"status": "success", "command_executed": command, "output": output}), 200
    except subprocess.CalledProcessError as exc:
        return jsonify({"status": "error", "command_executed": command, "output": exc.output}), 500
    except Exception as err:
        return jsonify({"status": "error", "message": str(err)}), 500


@app.route("/api/v1/metrics/query", methods=["GET"])
def query_metrics():
    """
    SAST Vector 3: SQL Injection Vulnerability.
    Vulnerability: Direct string formatting into SQL query.
    Detected by: Cortex SAST engine.
    """
    category = request.args.get("category", "system")
    conn = sqlite3.connect(DATA_STORE_PATH)
    cursor = conn.cursor()

    # Intentional SQLi vulnerability
    query = f"SELECT id, node_identifier, metric_category, raw_payload, recorded_at FROM system_telemetry WHERE metric_category = '{category}'"
    try:
        cursor.execute(query)
        rows = cursor.fetchall()
        results = [
            {"id": r[0], "node": r[1], "category": r[2], "payload": r[3], "timestamp": r[4]}
            for r in rows
        ]
        return jsonify({"query": query, "count": len(results), "records": results}), 200
    except Exception as err:
        return jsonify({"status": "error", "query": query, "error": str(err)}), 500
    finally:
        conn.close()


@app.route("/api/v1/data/dspm-sample", methods=["GET"])
def view_data_vault():
    """
    DSPM Vector: Endpoint returning sensitive data exposure metadata.
    Exposes locations of customer billing records for DSPM policy audits.
    """
    target_path = os.path.join(STORAGE_VAULT_MOUNT, "customer_billing_records.csv")
    exists = os.path.exists(target_path)
    file_size = os.path.getsize(target_path) if exists else 0

    return jsonify({
        "storage_asset": target_path,
        "contains_pci_dss": True,
        "contains_pii": True,
        "classification": "RESTRICTED_CONFIDENTIAL",
        "file_bytes": file_size,
        "cloud_sync_bucket": os.environ.get("S3_DATA_VAULT_BUCKET", "unconfigured")
    }), 200


if __name__ == "__main__":
    initialize_storage_vault()
    # Intentionally running on 0.0.0.0 in debug mode (insecure configuration)
    app.run(host="0.0.0.0", port=8080, debug=True)
