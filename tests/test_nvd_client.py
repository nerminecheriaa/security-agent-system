from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
import requests

from utils.nvd_client import NVDError, search_cves


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
