from unittest.mock import MagicMock

import requests

from agents.researcher import researcher_agent

NVD_RESPONSE = {
    "totalResults": 2,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2008-0001",
                "published": "2008-01-02T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "Old bug."}],
                "metrics": {
                    "cvssMetricV2": [
                        {"cvssData": {"baseScore": 4.3}, "baseSeverity": "MEDIUM"}
                    ]
                },
            }
        },
        {
            "cve": {
                "id": "CVE-2021-44228",
                "published": "2021-12-10T10:15:09.143",
                "descriptions": [
                    {"lang": "es", "value": "Descripción"},
                    {"lang": "en", "value": "Apache Log4j2 JNDI RCE."},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}
                    ]
                },
            }
        },
    ]
}


def mock_nvd(monkeypatch, *responses, exc=None):
    """
    Remplace requests.get : renvoie les réponses JSON dans l'ordre des appels.
    """
    calls = []

    def fake_get(url, params=None, headers=None, timeout=None):
        calls.append({"url": url, "params": params, "headers": headers, "timeout": timeout})
        if exc:
            raise exc
        response = MagicMock()
        response.json.return_value = responses[len(calls) - 1]
        response.raise_for_status.return_value = None
        return response

    monkeypatch.setattr("utils.nvd_client.requests.get", fake_get)
    return calls


def test_researcher_parses_nvd_response(monkeypatch):
    calls = mock_nvd(monkeypatch, NVD_RESPONSE)

    result = researcher_agent("log4j", max_results=2)

    params = calls[0]["params"]
    assert params["keywordSearch"] == "log4j"
    assert params["resultsPerPage"] == 2
    assert result["keyword"] == "log4j"
    assert result["count"] == 2
    assert result["message"] is None
    # Plus récente d'abord
    assert result["cves"][0] == {
        "id": "CVE-2021-44228",
        "description": "Apache Log4j2 JNDI RCE.",
        "score": 10.0,
        "severity": "CRITICAL",
        "published": "2021-12-10",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
    }
    # CVSS v2 : la sévérité est au niveau du metric, pas dans cvssData
    assert result["cves"][1]["score"] == 4.3
    assert result["cves"][1]["severity"] == "MEDIUM"


def test_researcher_forwards_days_and_severity(monkeypatch):
    calls = mock_nvd(monkeypatch, {"totalResults": 0, "vulnerabilities": []})

    researcher_agent("apache", max_results=3, days=7, severity="HIGH")

    params = calls[0]["params"]
    assert params["cvssV3Severity"] == "HIGH"
    assert params["resultsPerPage"] == 3


def test_researcher_explicit_message_when_no_results(monkeypatch):
    mock_nvd(monkeypatch, {"totalResults": 0, "vulnerabilities": []})

    result = researcher_agent("unknownproduct", severity="CRITICAL")

    assert result["cves"] == []
    assert result["count"] == 0
    assert "Aucune CVE" in result["message"]
    assert "120 derniers jours" in result["message"]
    assert "unknownproduct" in result["message"]
    assert "CRITICAL" in result["message"]


def test_researcher_without_keyword_uses_30_days(monkeypatch):
    mock_nvd(monkeypatch, {"totalResults": 0, "vulnerabilities": []})

    result = researcher_agent()

    assert result["keyword"] is None
    assert "30 derniers jours" in result["message"]


def test_researcher_filters_nvd_errors(monkeypatch):
    mock_nvd(monkeypatch, exc=requests.ConnectionError("down"))

    result = researcher_agent("apache")

    assert result["cves"] == []
    assert result["count"] == 0
    assert "NVD API error" in result["message"]
