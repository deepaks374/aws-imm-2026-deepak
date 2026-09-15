"""
CloudPulse Analytics Engine - Telemetry Ingestion and Data Processing Gateway.
Enterprise microservice demonstrating cloud-native application flows with intentional
security anti-patterns inspired by OWASP Juice Shop and Top Ten for CNAPP SAST,
runtime posture, and active attack validation.
"""

import os
import json
import sqlite3
import subprocess
import logging
import base64
import pickle
import urllib.request
import tempfile
import hashlib
import random
from flask import Flask, request, jsonify, render_template_string, Response

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# ==============================================================================
# SAST Vector: Hardcoded High-Entropy Secrets & API Keys
# Detected by: Cortex Code Security (Secret Scanning & SAST)
# ==============================================================================
PRIMARY_AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
PRIMARY_AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
STRIPE_INTEGRATION_LIVE_KEY = "sk_live_51Mz000CloudPulse999EnterpriseSecretKeyToken"
DATABASE_ADMIN_CONNECTION_URI = "postgres://telemetry_admin:SuperSecretAdminPassw0rd2026!@telemetry-rds.internal.net:5432/cloudpulse_prod"
JWT_INSECURE_SECRET = "cloudpulse-secret-key-12345"
GITHUB_PERSONAL_ACCESS_TOKEN = "ghp_11223344556677889900aabbccddeeffgghh"
SLACK_WEBHOOK_INTEGRATION_KEY = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
SENDGRID_PRODUCTION_API_KEY = "SG.99887766554433221100aa.bbccddeeffgghhiijjkkllmmnnooppqqrrssttuuvv"
OPENAI_INTEGRATION_KEY = "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz1234567890"

# ==============================================================================
# Additional Code Weaknesses for SAST (Cortex Code Security / SonarQube / Semgrep):
# 1. Broken / Insecure Cryptographic Hash (MD5 & SHA1 usage for security sensitive hashing)
# 2. Insecure Randomness (random.random() instead of secrets module)
# 3. Path Traversal Flaw (unrestricted file retrieval)
# 4. XML External Entity (XXE) Injection
# ==============================================================================

def insecure_generate_hash(data: str) -> str:
    """SAST Flaw: Use of weak hash function MD5."""
    return hashlib.md5(data.encode()).hexdigest()

def insecure_generate_token() -> str:
    """SAST Flaw: Use of cryptographically insecure pseudo-random number generator."""
    return str(random.random())

DEFAULT_DATA_DIR = os.environ.get("DATA_STORE_DIR", tempfile.gettempdir())
DATA_STORE_PATH = os.environ.get("DATA_STORE_PATH", os.path.join(DEFAULT_DATA_DIR, "telemetry_vault.db"))
STORAGE_VAULT_MOUNT = os.environ.get("STORAGE_VAULT_MOUNT", os.path.join(DEFAULT_DATA_DIR, "storage-vault"))

# In-memory document collection for NoSQL-like store (similar to Juice Shop's MarsDB / product reviews)
DOCUMENT_REVIEWS = [
    {"id": "REV-101", "product": "CloudPulse Agent", "author": "admin@cloudpulse.io", "rating": 5, "comment": "Robust telemetry collector."},
    {"id": "REV-102", "product": "CloudPulse Agent", "author": "user@client.corp", "rating": 4, "comment": "Good performance on EKS."},
    {"id": "REV-103", "product": "DSPM Analyzer", "author": "compliance@fintech.io", "rating": 5, "comment": "Accurately detects PCI data."},
]


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
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT,
            email TEXT,
            api_token TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS customer_orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id TEXT,
            item TEXT,
            amount REAL,
            tracking_code TEXT
        )
    """)

    # Seed users if empty
    cursor.execute("SELECT COUNT(*) FROM user_accounts")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO user_accounts (username, password, role, email, api_token) VALUES ('admin', 'admin123', 'admin', 'admin@cloudpulse.io', 'adm-tok-998877')")
        cursor.execute("INSERT INTO user_accounts (username, password, role, email, api_token) VALUES ('deepak', 'operatorPass2026', 'operator', 'deepak@cloudpulse.io', 'usr-tok-112233')")
        cursor.execute("INSERT INTO user_accounts (username, password, role, email, api_token) VALUES ('analyst', 'analystPass!', 'viewer', 'analyst@cloudpulse.io', 'usr-tok-445566')")

    # Seed orders if empty
    cursor.execute("SELECT COUNT(*) FROM customer_orders")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO customer_orders (customer_id, item, amount, tracking_code) VALUES ('CP-1001', 'CloudPulse Pro License', 4999.00, 'TRK-001')")
        cursor.execute("INSERT INTO customer_orders (customer_id, item, amount, tracking_code) VALUES ('CP-1002', 'DSPM Cloud Vault Add-on', 12500.00, 'TRK-002')")

    conn.commit()
    conn.close()


@app.route("/", methods=["GET"])
def health_status():
    """Standard health probe endpoint."""
    return jsonify({
        "service": "cloudpulse-telemetry-engine",
        "status": "operational",
        "version": "2.6.0",
        "environment": os.environ.get("APP_ENV", "production"),
        "capabilities": [
            "SQL Injection (SQLi)",
            "NoSQL Injection (NoSQLi)",
            "Broken Authentication",
            "Cross-Site Scripting (XSS / SSTI)",
            "Insecure Deserialization",
            "Server-Side Request Forgery (SSRF)",
            "Broken Access Control (B2B IDOR)",
            "Security Misconfigurations",
            "Sensitive Data Exposure / DSPM",
            "Path Traversal & Arbitrary File Read",
            "Weak Cryptography & Predictable Token Generation"
        ]
    }), 200


# ==============================================================================
# Path Traversal Vulnerability (Cortex Code Security / SAST Target)
# ==============================================================================
@app.route("/api/v1/system/file-view", methods=["GET"])
def view_system_file():
    """
    SAST Flaw: Path Traversal (Arbitrary File Read)
    User controlled filename passed without path sanitization.
    """
    filename = request.args.get("file", "customer_billing_records.csv")
    filepath = os.path.join(STORAGE_VAULT_MOUNT, filename)
    try:
        if os.path.exists(filepath):
            with open(filepath, "r", errors="ignore") as f:
                content = f.read(4000)
            return jsonify({"path": filepath, "content": content}), 200
        return jsonify({"status": "not_found", "path": filepath}), 404
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


# ==============================================================================
# 1. SQL Injection (SQLi)
# Juice Shop Reference: routes/search.ts, routes/login.ts
# ==============================================================================
@app.route("/api/v1/metrics/query", methods=["GET"])
def query_metrics():
    """
    SQL Injection Vulnerability via query parameter.
    Attacker can bypass filtering or extract arbitrary tables with UNION SELECT.
    """
    category = request.args.get("category", "system")
    conn = sqlite3.connect(DATA_STORE_PATH)
    cursor = conn.cursor()

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


@app.route("/api/v1/auth/sql-login", methods=["POST"])
def sql_login():
    """
    Classic SQLi Authentication Bypass (Juice Shop 'Login Admin' challenge).
    Payload example: ' OR 1=1 --
    """
    data = request.get_json(silent=True) or request.form or {}
    username = data.get("username", "")
    password = data.get("password", "")

    conn = sqlite3.connect(DATA_STORE_PATH)
    cursor = conn.cursor()
    query = f"SELECT id, username, role, email FROM user_accounts WHERE username = '{username}' AND password = '{password}'"
    try:
        cursor.execute(query)
        user = cursor.fetchone()
        if user:
            return jsonify({
                "status": "authenticated",
                "user": {"id": user[0], "username": user[1], "role": user[2], "email": user[3]},
                "token": f"bearer-mock-token-for-{user[1]}"
            }), 200
        return jsonify({"status": "failed", "message": "Invalid username or password"}), 401
    except Exception as err:
        return jsonify({"status": "error", "query": query, "error": str(err)}), 500
    finally:
        conn.close()


# ==============================================================================
# 2. NoSQL Injection (NoSQLi)
# Juice Shop Reference: routes/showProductReviews.ts, routes/updateProductReviews.ts
# ==============================================================================
@app.route("/api/v1/nosql/reviews", methods=["GET", "POST"])
def nosql_reviews():
    """
    NoSQL-style injection via operator evaluation ($ne, $regex, or sleep).
    When queried with JSON filters like {"author": {"$ne": null}}, all reviews are dumped.
    """
    global DOCUMENT_REVIEWS
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        author = data.get("author")

        # Insecure evaluation imitating MongoDB/MarsDB injection in Juice Shop
        if isinstance(author, dict):
            # Operator injection like {"$ne": null} or {"$regex": ".*"}
            if "$ne" in author:
                target_val = author["$ne"]
                matched = [r for r in DOCUMENT_REVIEWS if r.get("author") != target_val]
                return jsonify({"nosql_filter": data, "count": len(matched), "data": matched}), 200
            elif "$regex" in author:
                import re
                regex = re.compile(author["$regex"])
                matched = [r for r in DOCUMENT_REVIEWS if regex.search(str(r.get("author", "")))]
                return jsonify({"nosql_filter": data, "count": len(matched), "data": matched}), 200

        # Exact match fallback
        matched = [r for r in DOCUMENT_REVIEWS if r.get("author") == author]
        return jsonify({"count": len(matched), "data": matched}), 200

    # GET request lists all or filters by author query param
    author_param = request.args.get("author")
    if author_param:
        results = [r for r in DOCUMENT_REVIEWS if author_param in str(r.get("author", ""))]
    else:
        results = DOCUMENT_REVIEWS
    return jsonify({"count": len(results), "reviews": results}), 200


# ==============================================================================
# 3. Broken Authentication & Session Management
# Juice Shop Reference: routes/currentUser.ts, weak JWT verification, credential stuffing
# ==============================================================================
@app.route("/api/v1/auth/session-validate", methods=["GET"])
def validate_session():
    """
    Broken Authentication Vector:
    1. Accepts 'none' algorithm or unsigned tokens.
    2. Allows authentication via client-controlled headers (X-Authenticated-User) without cryptographic signature.
    """
    custom_user = request.headers.get("X-Authenticated-User")
    auth_header = request.headers.get("Authorization", "")

    # Insecure bypass via spoofable header
    if custom_user:
        return jsonify({
            "status": "authenticated",
            "auth_method": "Header-Impersonation-Flaw",
            "user": custom_user,
            "role": "admin" if custom_user == "admin" else "user"
        }), 200

    # Insecure base64-only token decode without signature check
    if auth_header.startswith("Bearer "):
        raw_token = auth_header.split(" ")[1]
        try:
            parts = raw_token.split(".")
            if len(parts) >= 2:
                # Decodes payload ignoring signature verification entirely
                padding = "=" * (4 - (len(parts[1]) % 4))
                payload = json.loads(base64.b64decode(parts[1] + padding).decode("utf-8"))
                return jsonify({
                    "status": "authenticated",
                    "auth_method": "Unverified-JWT-Payload",
                    "user": payload.get("username", "anonymous"),
                    "role": payload.get("role", "viewer")
                }), 200
        except Exception:
            pass

    return jsonify({"status": "unauthorized", "message": "Missing or invalid credentials"}), 401


# ==============================================================================
# 4. Cross-Site Scripting (XSS) & Server-Side Template Injection (SSTI)
# Juice Shop Reference: views/templates, search DOM XSS, reflective feedback
# ==============================================================================
@app.route("/api/v1/feedback/preview", methods=["GET", "POST"])
def preview_feedback():
    """
    Reflected XSS / SSTI via Jinja2 Template rendering without auto-escaping.
    Juice Shop reference: Server-Side Template Injection & DOM XSS.
    Payload: {{ 7 * 7 }} or <script>alert(document.cookie)</script>
    """
    user_input = request.args.get("message")
    if not user_input and request.is_json:
        user_input = request.get_json().get("message", "")
    elif not user_input and request.form:
        user_input = request.form.get("message", "")

    if not user_input:
        user_input = "Great monitoring capabilities!"

    # Vulnerable template rendering
    template_str = f"""
    <!DOCTYPE html>
    <html>
    <head><title>CloudPulse Feedback Preview</title></head>
    <body style="font-family: sans-serif; padding: 20px;">
        <h2>User Feedback Preview</h2>
        <div id="feedback-content" style="border: 1px solid #ccc; padding: 15px; border-radius: 5px;">
            {user_input}
        </div>
    </body>
    </html>
    """
    rendered = render_template_string(template_str)
    return Response(rendered, mimetype="text/html")


# ==============================================================================
# 5. Insecure Deserialization
# Juice Shop Reference: routes/b2bOrder.ts (eval/safeEval abuse, YAML/JSON deserialization)
# ==============================================================================
@app.route("/api/v1/b2b/batch-order", methods=["POST"])
def b2b_batch_order():
    """
    Insecure Deserialization of base64-encoded Python pickle or YAML payload.
    Allows arbitrary code execution when unpickling untrusted payload.
    """
    data = request.get_json(silent=True) or {}
    encoded_payload = data.get("serialized_payload", "")

    if not encoded_payload:
        return jsonify({"status": "error", "message": "Missing 'serialized_payload' field"}), 400

    try:
        raw_bytes = base64.b64decode(encoded_payload)
        # Intentional Insecure Deserialization
        obj = pickle.loads(raw_bytes)
        return jsonify({
            "status": "success",
            "message": "Payload deserialized successfully",
            "received_type": str(type(obj)),
            "content": str(obj)
        }), 200
    except Exception as exc:
        return jsonify({"status": "error", "message": f"Deserialization failed: {str(exc)}"}), 500


# ==============================================================================
# 6. Server-Side Request Forgery (SSRF)
# Juice Shop Reference: routes/profileImageUrlUpload.ts, cloud metadata probing
# ==============================================================================
@app.route("/api/v1/integrations/fetch-webhook", methods=["POST"])
def fetch_external_webhook():
    """
    SSRF Vulnerability: Server fetches arbitrary user-provided URL without validation.
    Enables attackers to probe EC2 Instance Metadata Service (IMDS: 169.254.169.254)
    or internal Kubernetes ClusterIP services.
    """
    data = request.get_json(silent=True) or {}
    target_url = data.get("webhook_url", "")

    if not target_url:
        return jsonify({"status": "error", "message": "Missing 'webhook_url'"}), 400

    try:
        req = urllib.request.Request(
            target_url,
            headers={"User-Agent": "CloudPulse-Webhook-Service/2.6"}
        )
        with urllib.request.urlopen(req, timeout=3) as response:
            body = response.read().decode("utf-8", errors="replace")
            return jsonify({
                "status": "success",
                "fetched_url": target_url,
                "http_status": response.status,
                "response_body": body[:2000]
            }), 200
    except Exception as exc:
        return jsonify({"status": "error", "target_url": target_url, "error": str(exc)}), 502


# ==============================================================================
# 7. Broken Access Control (IDOR / Vertical & Horizontal Privilege Escalation)
# Juice Shop Reference: routes/basket.ts, routes/orderHistory.ts
# ==============================================================================
@app.route("/api/v1/orders/<order_id>", methods=["GET"])
def view_order(order_id):
    """
    Insecure Direct Object Reference (IDOR):
    Orders are accessed by ID without verifying if the caller owns the record.
    """
    conn = sqlite3.connect(DATA_STORE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, customer_id, item, amount, tracking_code FROM customer_orders WHERE id = ? OR tracking_code = ?", (order_id, order_id))
    order = cursor.fetchone()
    conn.close()

    if order:
        return jsonify({
            "order_id": order[0],
            "customer_id": order[1],
            "purchased_item": order[2],
            "billing_amount": order[3],
            "tracking_code": order[4]
        }), 200
    return jsonify({"status": "not_found", "message": f"Order {order_id} not found"}), 404


@app.route("/api/v1/admin/users", methods=["GET"])
def list_users_unprotected():
    """
    Broken Access Control / Missing Function Level Access Control:
    Administrative user management endpoint accessible without authorization check.
    """
    conn = sqlite3.connect(DATA_STORE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role, email, api_token FROM user_accounts")
    users = [
        {"id": u[0], "username": u[1], "role": u[2], "email": u[3], "api_token": u[4]}
        for u in cursor.fetchall()
    ]
    conn.close()
    return jsonify({"count": len(users), "users": users}), 200


# ==============================================================================
# 8. Security Misconfigurations
# Juice Shop Reference: directory listing, debug info leakage, command execution
# ==============================================================================
@app.route("/api/v1/diagnostics/ping", methods=["POST"])
def network_diagnostics():
    """
    Remote Code Execution / Command Injection flaw (shell=True with unescaped input).
    Detected by: Cortex Code Security & Cortex K8s Runtime Agent.
    """
    data = request.get_json(silent=True) or {}
    target_host = data.get("target_host", "127.0.0.1")

    command = f"ping -c 2 {target_host}"
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True, timeout=5)
        return jsonify({"status": "success", "command_executed": command, "output": output}), 200
    except subprocess.CalledProcessError as exc:
        return jsonify({"status": "error", "command_executed": command, "output": exc.output}), 500
    except Exception as err:
        return jsonify({"status": "error", "message": str(err)}), 500


@app.route("/api/v1/debug/env", methods=["GET"])
def leak_debug_environment():
    """
    Security Misconfiguration: Exposed debug endpoint revealing process environment,
    internal paths, and application secrets.
    """
    safe_env = {k: v for k, v in os.environ.items()}
    return jsonify({
        "debug_mode": True,
        "framework": "Flask 2.2.5",
        "environment_variables": safe_env,
        "internal_paths": {
            "data_store": DATA_STORE_PATH,
            "vault_mount": STORAGE_VAULT_MOUNT
        }
    }), 200


# ==============================================================================
# 9. Sensitive Data Exposure & DSPM
# Juice Shop Reference: confidential documents, FTP access log disclosure, PII leaks
# ==============================================================================
@app.route("/api/v1/data/dspm-sample", methods=["GET"])
def view_data_vault():
    """
    DSPM Vector: Exposes metadata regarding location and structure of unencrypted PII & PCI-DSS data.
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


@app.route("/api/v1/data/export-pii", methods=["GET"])
def export_pii_records():
    """
    Sensitive Data Exposure: Unrestricted extraction of customer PII and credit cards.
    """
    target_path = os.path.join(STORAGE_VAULT_MOUNT, "customer_billing_records.csv")
    if os.path.exists(target_path):
        with open(target_path, "r") as f:
            content = f.read()
        return Response(content, mimetype="text/csv")
    return jsonify({"status": "error", "message": "Storage vault not initialized"}), 404


if __name__ == "__main__":
    initialize_storage_vault()
    # Insecure configuration: running on 0.0.0.0 with debug=True
    app.run(host="0.0.0.0", port=8080, debug=True)
