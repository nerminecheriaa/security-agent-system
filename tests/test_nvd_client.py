from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
import requests

from utils.nvd_client import CVENotFoundError, NVDError, get_cve, search_cves


def make_cve(cve_id, published):
    return {"cve": {"id": cve_id, "published": published, "descriptions": [], "metrics": {}}}


def mock_get(monkeypatch, *responses, exc=None):
    calls = []

    def fake_get(url, params=None, headers=None, timeout=None):
        calls.append({"params": params, "headers": headers})
        if exc:
            raise exc
        response = MagicMock()
        response.json.return_value = responses[len(calls) - 1]
        response.raise_for_status.return_value = None
        return response

    monkeypatch.setattr("utils.nvd_client.requests.get", fake_get)
    return calls


EMPTY = {"totalResults": 0, "vulnerabilities": []}


def parse_date(value):
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.000").replace(tzinfo=timezone.utc)


def test_date_window_defaults_to_120_days_with_keyword(monkeypatch):
    calls = mock_get(monkeypatch, EMPTY)

    search_cves("apache")

    params = calls[0]["params"]
    start, end = parse_date(params["pubStartDate"]), parse_date(params["pubEndDate"])
    assert end - start == timedelta(days=120)
    assert abs(datetime.now(timezone.utc) - end) < timedelta(minutes=1)
    assert params["keywordSearch"] == "apache"
    assert "noRejected" in params


def test_date_window_defaults_to_30_days_without_keyword(monkeypatch):
    calls = mock_get(monkeypatch, EMPTY)

    search_cves()

    params = calls[0]["params"]
    assert parse_date(params["pubEndDate"]) - parse_date(params["pubStartDate"]) == timedelta(days=30)
    assert "keywordSearch" not in params


def test_blank_keyword_is_treated_as_none(monkeypatch):
    calls = mock_get(monkeypatch, EMPTY)

    search_cves("   ")

    params = calls[0]["params"]
    assert "keywordSearch" not in params
    assert parse_date(params["pubEndDate"]) - parse_date(params["pubStartDate"]) == timedelta(days=30)


def test_explicit_days_and_severity(monkeypatch):
    calls = mock_get(monkeypatch, EMPTY)

    search_cves("apache", days=7, severity="CRITICAL", limit=10)

    params = calls[0]["params"]
    assert parse_date(params["pubEndDate"]) - parse_date(params["pubStartDate"]) == timedelta(days=7)
    assert params["cvssV3Severity"] == "CRITICAL"
    assert params["resultsPerPage"] == 10


def test_single_call_when_total_fits_in_limit(monkeypatch):
    page = {"totalResults": 2, "vulnerabilities": [
        make_cve("CVE-A", "2026-09-01T00:00:00.000"),
        make_cve("CVE-B", "2026-09-02T00:00:00.000"),
    ]}
    calls = mock_get(monkeypatch, page)

    cves = search_cves("apache", limit=5)

    assert len(calls) == 1
    assert [c["id"] for c in cves] == ["CVE-B", "CVE-A"]


def test_fetches_last_page_when_more_results_than_limit(monkeypatch):
    first = {"totalResults": 10, "vulnerabilities": [
        make_cve("CVE-OLD-1", "2026-07-01T00:00:00.000"),
        make_cve("CVE-OLD-2", "2026-07-02T00:00:00.000"),
    ]}
    last = {"totalResults": 10, "vulnerabilities": [
        make_cve("CVE-NEW-1", "2026-10-01T00:00:00.000"),
        make_cve("CVE-NEW-2", "2026-10-03T00:00:00.000"),
    ]}
    calls = mock_get(monkeypatch, first, last)

    cves = search_cves("apache", limit=2)

    assert len(calls) == 2
    assert calls[1]["params"]["startIndex"] == 8
    # Les autres paramètres sont identiques entre les deux appels
    assert {k: v for k, v in calls[1]["params"].items() if k != "startIndex"} == calls[0]["params"]
    assert [c["id"] for c in cves] == ["CVE-NEW-2", "CVE-NEW-1"]


def test_parses_cvss_v4_first(monkeypatch):
    cve = make_cve("CVE-X", "2026-10-01T00:00:00.000")
    cve["cve"]["metrics"] = {
        "cvssMetricV40": [{"cvssData": {"baseScore": 9.3, "baseSeverity": "CRITICAL"}}],
        "cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}],
    }
    mock_get(monkeypatch, {"totalResults": 1, "vulnerabilities": [cve]})

    result = search_cves("x")[0]

    assert result["score"] == 9.3
    assert result["severity"] == "CRITICAL"


def test_unscored_cve_has_none_score(monkeypatch):
    mock_get(monkeypatch, {"totalResults": 1, "vulnerabilities": [make_cve("CVE-X", "2026-10-01T00:00:00.000")]})

    result = search_cves("x")[0]

    assert result["score"] is None
    assert result["severity"] is None


def test_api_key_header_sent_when_configured(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "secret")
    calls = mock_get(monkeypatch, EMPTY)

    search_cves("apache")

    assert calls[0]["headers"] == {"apiKey": "secret"}


def test_no_api_key_header_by_default(monkeypatch):
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    calls = mock_get(monkeypatch, EMPTY)

    search_cves("apache")

    assert calls[0]["headers"] == {}


@pytest.mark.parametrize("kwargs", [
    {"days": 0},
    {"days": 121},
    {"limit": 0},
    {"limit": 51},
    {"severity": "URGENT"},
])
def test_invalid_arguments_raise_value_error(kwargs):
    # Aucun mock : la validation doit échouer avant tout appel réseau
    with pytest.raises(ValueError):
        search_cves("apache", **kwargs)


def test_network_error_raises_nvd_error(monkeypatch):
    mock_get(monkeypatch, exc=requests.ConnectionError("down"))

    with pytest.raises(NVDError, match="down"):
        search_cves("apache")


# ── get_cve ────────────────────────────────────────────────────────────────
# Structure calquée sur la réponse réelle de NVD pour cveId=CVE-2021-44228
LOG4SHELL = {"totalResults": 1, "vulnerabilities": [{"cve": {
    "id": "CVE-2021-44228",
    "published": "2021-12-10T10:15:09.143",
    "lastModified": "2026-08-11T19:33:44.513",
    "vulnStatus": "Analyzed",
    "descriptions": [
        {"lang": "en", "value": "Apache Log4j2 JNDI RCE."},
        {"lang": "es", "value": "Descripción"},
    ],
    "metrics": {
        "cvssMetricV31": [
            {"source": "nvd@nist.gov", "type": "Primary", "cvssData": {
                "version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "baseScore": 10.0, "baseSeverity": "CRITICAL"}},
            {"source": "cna@example.org", "type": "Secondary", "cvssData": {
                "version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "baseScore": 9.0, "baseSeverity": "CRITICAL"}},
        ],
        "cvssMetricV2": [
            {"source": "nvd@nist.gov", "type": "Primary", "baseSeverity": "HIGH", "cvssData": {
                "version": "2.0", "vectorString": "AV:N/AC:M/Au:N/C:C/I:C/A:C", "baseScore": 9.3}},
        ],
        # Métrique non CVSS, sans cvssData : doit être ignorée
        "ssvcV203": [{"source": "cna@example.org", "ssvcData": {}}],
    },
    "weaknesses": [
        {"source": "security@apache.org", "type": "Secondary", "description": [
            {"lang": "en", "value": "CWE-20"}, {"lang": "en", "value": "CWE-502"}]},
        {"source": "nvd@nist.gov", "type": "Primary", "description": [
            {"lang": "en", "value": "CWE-917"}, {"lang": "en", "value": "CWE-502"}]},
    ],
    "references": [
        {"url": f"https://example.org/ref{i}", "source": "x", "tags": ["Patch"] if i == 0 else []}
        for i in range(7)
    ],
}}]}


def test_get_cve_returns_all_details(monkeypatch):
    calls = mock_get(monkeypatch, LOG4SHELL)

    cve = get_cve("CVE-2021-44228")

    assert calls[0]["params"] == {"cveId": "CVE-2021-44228"}
    assert cve["id"] == "CVE-2021-44228"
    assert cve["description"] == "Apache Log4j2 JNDI RCE."
    assert cve["score"] == 10.0
    assert cve["severity"] == "CRITICAL"
    assert cve["published"] == "2021-12-10"
    assert cve["url"] == "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    assert cve["last_modified"] == "2026-08-11"
    assert cve["vuln_status"] == "Analyzed"
    assert cve["cwes"] == ["CWE-20", "CWE-502", "CWE-917"]
    assert cve["cvss"] == [
        {"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
         "score": 10.0, "severity": "CRITICAL", "source": "nvd@nist.gov", "type": "Primary"},
        {"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
         "score": 9.0, "severity": "CRITICAL", "source": "cna@example.org", "type": "Secondary"},
        # CVSS v2 : la sévérité est au niveau du metric, pas dans cvssData
        {"version": "2.0", "vector": "AV:N/AC:M/Au:N/C:C/I:C/A:C",
         "score": 9.3, "severity": "HIGH", "source": "nvd@nist.gov", "type": "Primary"},
    ]
    assert len(cve["references"]) == 5
    assert cve["references"][0] == {"url": "https://example.org/ref0", "tags": ["Patch"]}


def test_get_cve_unscored(monkeypatch):
    raw = {"id": "CVE-2026-12345", "published": "2026-10-03T08:00:00.000",
           "vulnStatus": "Received", "descriptions": [], "metrics": {}}
    mock_get(monkeypatch, {"totalResults": 1, "vulnerabilities": [{"cve": raw}]})

    cve = get_cve("CVE-2026-12345")

    assert cve["score"] is None
    assert cve["severity"] is None
    assert cve["vuln_status"] == "Received"
    assert cve["last_modified"] is None
    assert cve["cwes"] == []
    assert cve["cvss"] == []
    assert cve["references"] == []


def test_get_cve_not_found(monkeypatch):
    # Comportement réel : HTTP 200 avec totalResults = 0
    mock_get(monkeypatch, {"resultsPerPage": 0, "startIndex": 0, "totalResults": 0, "vulnerabilities": []})

    with pytest.raises(CVENotFoundError, match="CVE-2099-99999 introuvable"):
        get_cve("CVE-2099-99999")


@pytest.mark.parametrize("cve_id", [
    "",
    "CVE-2021-123",
    "CVE-21-44228",
    "cve-2021-44228",
    " CVE-2021-44228",
    "CVE-2021-44228\n",
    "CVE-2021-44228; DROP",
    "CVE-٢٠٢١-44228",  # chiffres non ASCII
])
def test_get_cve_invalid_id_makes_no_network_call(monkeypatch, cve_id):
    calls = mock_get(monkeypatch, LOG4SHELL)

    with pytest.raises(ValueError, match="Identifiant CVE invalide"):
        get_cve(cve_id)

    assert calls == []


def test_get_cve_network_error_raises_nvd_error(monkeypatch):
    mock_get(monkeypatch, exc=requests.ConnectionError("down"))

    with pytest.raises(NVDError, match="down"):
        get_cve("CVE-2021-44228")


def test_get_cve_sends_api_key_header(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "secret")
    calls = mock_get(monkeypatch, LOG4SHELL)

    get_cve("CVE-2021-44228")

    assert calls[0]["headers"] == {"apiKey": "secret"}
