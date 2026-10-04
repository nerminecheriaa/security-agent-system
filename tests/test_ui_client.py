from unittest.mock import MagicMock

import pytest
import requests

from ui import client
from ui.client import APIError, build_analyze_payload


def mock_request(monkeypatch, status=200, body=None, exc=None):
    calls = []

    def fake_request(method, url, timeout=None, **kwargs):
        calls.append({"method": method, "url": url, "timeout": timeout, **kwargs})
        if exc:
            raise exc
        response = MagicMock()
        response.status_code = status
        response.ok = status < 400
        response.json.return_value = body
        return response

    monkeypatch.setattr("ui.client.requests.request", fake_request)
    return calls


# ── Construction de la requête ─────────────────────────────────────────────
def test_payload_keeps_api_defaults_when_days_and_severity_not_chosen():
    assert build_analyze_payload("  apache ", 5) == {"keyword": "apache", "max_results": 5}


def test_payload_with_days_and_severity():
    assert build_analyze_payload("apache", 10, days=7, severity="HIGH") == {
        "keyword": "apache", "max_results": 10, "days": 7, "severity": "HIGH",
    }


@pytest.mark.parametrize("severity", [None, "Toutes", "URGENT"])
def test_payload_ignores_unknown_severity(severity):
    assert "severity" not in build_analyze_payload("apache", 5, severity=severity)


def test_analyze_posts_payload_with_timeout(monkeypatch):
    calls = mock_request(monkeypatch, body={"job_id": "abc"})

    result = client.analyze("apache", 5, days=30)

    assert result == {"job_id": "abc"}
    assert calls[0]["method"] == "POST"
    assert calls[0]["url"] == f"{client.API_URL}/analyze"
    assert calls[0]["json"] == {"keyword": "apache", "max_results": 5, "days": 30}
    assert calls[0]["timeout"] == (client.CONNECT_TIMEOUT, 60)


def test_history_and_result_routes(monkeypatch):
    calls = mock_request(monkeypatch, body={"total": 1, "jobs": [{"job_id": "abc"}]})

    assert client.get_history() == [{"job_id": "abc"}]
    client.get_result("abc")

    assert [c["url"] for c in calls] == [f"{client.API_URL}/history", f"{client.API_URL}/results/abc"]


# ── Gestion des erreurs ────────────────────────────────────────────────────
def test_unreachable_api(monkeypatch):
    mock_request(monkeypatch, exc=requests.ConnectionError("Max retries exceeded ... [WinError 10061]"))

    with pytest.raises(APIError, match="API injoignable") as exc_info:
        client.analyze("apache", 5)

    assert "WinError" not in str(exc_info.value)


def test_timeout(monkeypatch):
    mock_request(monkeypatch, exc=requests.ReadTimeout("read timed out"))

    with pytest.raises(APIError, match="Délai dépassé : l'API n'a pas répondu en 60 s"):
        client.analyze("apache", 5)


def test_validation_error_shows_field(monkeypatch):
    mock_request(monkeypatch, status=422, body={"detail": [
        {"loc": ["body", "keyword"], "msg": "String should have at least 2 characters", "type": "string_too_short"},
    ]})

    with pytest.raises(APIError) as exc_info:
        client.analyze("a", 5)

    assert str(exc_info.value) == "Paramètres invalides — keyword : String should have at least 2 characters"


def test_server_error_shows_detail(monkeypatch):
    mock_request(monkeypatch, status=500, body={"detail": "Analysis failed: GROQ_API_KEY is not set."})

    with pytest.raises(APIError, match=r"Erreur de l'API \(500\) : Analysis failed: GROQ_API_KEY is not set\."):
        client.analyze("apache", 5)


def test_unknown_job(monkeypatch):
    mock_request(monkeypatch, status=404, body={"detail": "Job 'zzz' not found."})

    with pytest.raises(APIError, match="Introuvable : Job 'zzz' not found."):
        client.get_result("zzz")


def test_api_keys_are_never_displayed(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "nvd-secret-value")
    mock_request(monkeypatch, status=500, body={
        "detail": "Analysis failed: invalid key gsk_AbC123xyz and nvd-secret-value",
    })

    with pytest.raises(APIError) as exc_info:
        client.analyze("apache", 5)

    message = str(exc_info.value)
    assert "gsk_AbC123xyz" not in message
    assert "nvd-secret-value" not in message
    assert message == "Erreur de l'API (500) : Analysis failed: invalid key *** and ***"
