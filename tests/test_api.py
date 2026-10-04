from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)


def test_health():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy",
        "agents": ["researcher", "summarizer", "report_writer"],
    }


def mock_nvd(monkeypatch, *responses):
    """
    Remplace requests.get : renvoie les réponses JSON dans l'ordre des appels.
    """
    calls = []

    def fake_get(url, params=None, headers=None, timeout=None):
        calls.append(params)
        response = MagicMock()
        response.json.return_value = responses[len(calls) - 1]
        response.raise_for_status.return_value = None
        return response

    monkeypatch.setattr("utils.nvd_client.requests.get", fake_get)
    return calls


def parse_date(value):
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.000")


NVD_RESPONSE = {
    "totalResults": 1,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2026-12345",
                "published": "2026-10-01T08:00:00.000",
                "descriptions": [{"lang": "en", "value": "Critical RCE."}],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                    ]
                },
            }
        }
    ],
}


def test_analyze_with_days_and_severity(monkeypatch, no_network):
    calls = mock_nvd(monkeypatch, NVD_RESPONSE)

    response = client.post(
        "/analyze",
        json={"keyword": "apache", "max_results": 3, "days": 7, "severity": "CRITICAL"},
    )

    assert response.status_code == 200
    params = calls[0]
    assert params["keywordSearch"] == "apache"
    assert params["cvssV3Severity"] == "CRITICAL"
    assert params["resultsPerPage"] == 3
    assert parse_date(params["pubEndDate"]) - parse_date(params["pubStartDate"]) == timedelta(days=7)

    body = response.json()
    assert body["keyword"] == "apache"
    assert body["status"] == "completed"
    assert body["cve_count"] == 1
    assert body["critical_count"] == 1
    assert body["message"] is None
    assert "CVE-2026-12345" in body["report"]
    assert "Mocked AI analysis." in body["report"]
    no_network.invoke.assert_called_once()


def test_analyze_no_results_returns_message(monkeypatch, no_network):
    mock_nvd(monkeypatch, {"totalResults": 0, "vulnerabilities": []})

    response = client.post("/analyze", json={"keyword": "nothingmatches", "severity": "HIGH"})

    assert response.status_code == 200
    body = response.json()
    assert body["cve_count"] == 0
    assert "Aucune CVE" in body["message"]
    assert "120 derniers jours" in body["message"]
    assert "nothingmatches" in body["message"]
    # Le message remplace le résumé générique dans le rapport
    assert body["message"] in body["report"]
    # Pas d'appel au LLM sans CVE
    no_network.invoke.assert_not_called()


@pytest.mark.parametrize("payload", [
    {"keyword": "apache", "days": 200},
    {"keyword": "apache", "severity": "URGENT"},
])
def test_analyze_rejects_invalid_parameters(payload):
    # Aucun mock NVD : la validation doit échouer avant tout appel réseau
    response = client.post("/analyze", json=payload)

    assert response.status_code == 422
