"""
Unit test suite for CloudPulse Telemetry Engine.
Runs in CI/CD before SAST and container build stages.
"""

import pytest
import os
import sys

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
    """Verify health endpoint responds with operational status."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.get_json()
    assert data["service"] == "cloudpulse-telemetry-engine"
    assert data["status"] == "operational"


def test_dspm_sample_endpoint(client):
    """Verify DSPM sample endpoint exposes sensitive data classification metadata."""
    response = client.get("/api/v1/data/dspm-sample")
    assert response.status_code == 200
    data = response.get_json()
    assert data["contains_pci_dss"] is True
    assert data["contains_pii"] is True
    assert data["classification"] == "RESTRICTED_CONFIDENTIAL"


def test_metrics_query_endpoint(client):
    """Verify metrics query endpoint functionality."""
    response = client.get("/api/v1/metrics/query?category=system")
    assert response.status_code == 200
    data = response.get_json()
    assert "records" in data
