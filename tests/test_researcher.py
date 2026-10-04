from unittest.mock import MagicMock

import requests

from agents.researcher import researcher_agent

NVD_RESPONSE = {
    "vulnerabilities": [
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
    ]
}


def mock_nvd(monkeypatch, json_data=None, exc=None):
    calls = []

    def fake_get(url, params=None, timeout=None):
        calls.append({"url": url, "params": params, "timeout": timeout})
        if exc:
            raise exc
        response = MagicMock()
        response.json.return_value = json_data
        response.raise_for_status.return_value = None
        return response

    monkeypatch.setattr("utils.nvd_client.requests.get", fake_get)
    return calls


def test_researcher_parses_nvd_response(monkeypatch):
    calls = mock_nvd(monkeypatch, NVD_RESPONSE)

    result = researcher_agent("log4j", max_results=2)

    assert calls[0]["params"] == {"keywordSearch": "log4j", "resultsPerPage": 2}
    assert result["keyword"] == "log4j"
    assert result["count"] == 2
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


def test_researcher_filters_nvd_errors(monkeypatch):
    mock_nvd(monkeypatch, exc=requests.ConnectionError("down"))

    result = researcher_agent("apache")

    assert result["cves"] == []
    assert result["count"] == 0
