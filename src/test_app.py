"""
Unit test suite for CloudPulse Telemetry Engine.
Tests all OWASP vulnerability endpoints inspired by Juice Shop:
SQLi, NoSQLi, Broken Authentication, XSS/SSTI, Insecure Deserialization,
SSRF, Broken Access Control (IDOR), Security Misconfigurations, and Sensitive Data Exposure.
"""

import pytest
import os
import sys
import base64
import pickle

# Ensure src path is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app import app, initialize_storage_vault


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        with app.app_context():
            initialize_storage_vault()
        yield client


def test_health_endpoint(client):
    """Verify health endpoint responds with operational status and capabilities."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.get_json()
    assert data["service"] == "cloudpulse-telemetry-engine"
    assert data["status"] == "operational"
    assert "capabilities" in data
    assert len(data["capabilities"]) >= 8


# 1. SQL Injection Tests
def test_sqli_metrics_query(client):
    """Verify SQLi on metrics query parameter."""
    # Classic SQLi UNION test or tautology
    response = client.get("/api/v1/metrics/query?category=' OR 1=1 --")
    assert response.status_code == 200
    data = response.get_json()
    assert "records" in data


def test_sqli_auth_bypass(client):
    """Verify SQLi authentication bypass (Juice Shop 'Login Admin' challenge)."""
    payload = {"username": "admin' --", "password": "arbitraryPassword"}
    response = client.post("/api/v1/auth/sql-login", json=payload)
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "authenticated"
    assert data["user"]["username"] == "admin"


# 2. NoSQL Injection Tests
def test_nosqli_reviews_operator_bypass(client):
    """Verify NoSQL operator injection with $ne."""
    payload = {"author": {"$ne": "nonexistent@target.corp"}}
    response = client.post("/api/v1/nosql/reviews", json=payload)
    assert response.status_code == 200
    data = response.get_json()
    assert data["count"] > 0


# 3. Broken Authentication Tests
def test_broken_auth_spoofed_header(client):
    """Verify authentication bypass using spoofable identity header."""
    headers = {"X-Authenticated-User": "admin"}
    response = client.get("/api/v1/auth/session-validate", headers=headers)
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "authenticated"
    assert data["role"] == "admin"


def test_broken_auth_unverified_jwt(client):
    """Verify authentication acceptance of unsigned base64 token."""
    dummy_payload = base64.b64encode(b'{"username":"deepak","role":"operator"}').decode("utf-8")
    forged_token = f"eyJhbGciOiJub25lIn0.{dummy_payload}.signatureskipped"
    headers = {"Authorization": f"Bearer {forged_token}"}
    response = client.get("/api/v1/auth/session-validate", headers=headers)
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "authenticated"
    assert data["user"] == "deepak"


# 4. XSS & SSTI Tests
def test_xss_ssti_feedback_preview(client):
    """Verify XSS / SSTI injection in feedback template."""
    payload = "<script>alert('XSS-Triggered')</script>"
    response = client.get(f"/api/v1/feedback/preview?message={payload}")
    assert response.status_code == 200
    assert b"<script>alert('XSS-Triggered')</script>" in response.data


# 5. Insecure Deserialization Tests
def test_insecure_deserialization(client):
    """Verify arbitrary object deserialization via Python pickle payload."""
    sample_data = {"action": "telemetry_sync", "batch_id": 9999}
    serialized = base64.b64encode(pickle.dumps(sample_data)).decode("utf-8")
    response = client.post("/api/v1/b2b/batch-order", json={"serialized_payload": serialized})
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    assert "telemetry_sync" in data["content"]


# 6. SSRF Tests
def test_ssrf_webhook_trigger(client):
    """Verify SSRF webhook dispatch endpoint accepts arbitrary target URLs."""
    response = client.post("/api/v1/integrations/fetch-webhook", json={"webhook_url": "http://127.0.0.1:8080/nonexistent"})
    # Either succeeds or returns 502 with error, verifying request execution
    assert response.status_code in [200, 502]


# 7. Broken Access Control Tests (IDOR)
def test_broken_access_control_order_idor(client):
    """Verify IDOR access to unowned customer order."""
    response = client.get("/api/v1/orders/1")
    assert response.status_code == 200
    data = response.get_json()
    assert "purchased_item" in data
    assert data["customer_id"] == "CP-1001"


def test_broken_access_control_admin_listing(client):
    """Verify unprotected administrative user list."""
    response = client.get("/api/v1/admin/users")
    assert response.status_code == 200
    data = response.get_json()
    assert data["count"] >= 3


# 8. Security Misconfigurations Tests
def test_security_misconfig_debug_env(client):
    """Verify debug environment endpoint leaks server variables."""
    response = client.get("/api/v1/debug/env")
    assert response.status_code == 200
    data = response.get_json()
    assert data["debug_mode"] is True
    assert "environment_variables" in data


# 9. Sensitive Data Exposure / DSPM Tests
def test_dspm_sample_endpoint(client):
    """Verify DSPM sample endpoint exposes sensitive data classification metadata."""
    response = client.get("/api/v1/data/dspm-sample")
    assert response.status_code == 200
    data = response.get_json()
    assert data["contains_pci_dss"] is True
    assert data["contains_pii"] is True
    assert data["classification"] == "RESTRICTED_CONFIDENTIAL"


def test_sensitive_data_exposure_csv_download(client):
    """Verify sensitive PII/credit card CSV data export."""
    response = client.get("/api/v1/data/export-pii")
    assert response.status_code == 200
    assert b"customer_id,full_name,email,tax_id_ssn,primary_card_number,cvv" in response.data
    assert b"Johnathan Vance" in response.data
