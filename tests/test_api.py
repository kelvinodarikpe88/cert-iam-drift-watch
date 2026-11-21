import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
KEY = {"x-api-key": "test-key"}


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


def payload():
    return {
        "certs": json.loads((FIXTURES / "certs.json").read_text())["certs"],
        "users": json.loads((FIXTURES / "iam.json").read_text())["users"],
        "as_of": "2026-11-21",
    }


def test_checks_are_documented(client):
    response = client.get("/v1/checks", headers=KEY)
    assert response.status_code == 200
    assert response.json()["count"] == 12


def test_report_needs_a_key(client):
    assert client.post("/v1/report", json=payload()).status_code == 401


def test_report_returns_findings_and_prose(client):
    response = client.post("/v1/report", headers=KEY, json=payload())
    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["findings"] == 12
    assert body["report_source"] == "template"
    assert body["findings"][0]["severity"] == "critical"


def test_bad_date_is_422(client):
    request = {**payload(), "as_of": "21-11-2026"}
    assert client.post("/v1/report", headers=KEY, json=request).status_code == 422


def test_certificate_without_not_after_is_422(client):
    request = {**payload(), "certs": [{"host": "x.example.com"}]}
    assert client.post("/v1/report", headers=KEY, json=request).status_code == 422


def test_empty_inventory_is_a_clean_report(client):
    response = client.post("/v1/report", headers=KEY, json={"as_of": "2026-11-21"})
    body = response.json()
    assert body["summary"]["findings"] == 0
    assert "nothing crossed a threshold" in body["report"]
