import re

from agents.report_writer import report_writer_agent

CVES = [
    {
        "id": "CVE-2021-44228",
        "description": "Apache Log4j2 JNDI RCE.",
        "score": 10.0,
        "severity": "CRITICAL",
        "published": "2021-12-10",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
    },
    {
        "id": "CVE-2008-0001",
        "description": "Old bug.",
        "score": "N/A",
        "severity": "N/A",
        "published": "2008-01-02",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2008-0001",
    },
]

SUMMARY = {
    "summary": "Patch Log4j immediately.",
    "critical_count": 1,
    "high_count": 0,
    "medium_count": 0,
}


def test_report_contains_overview_and_cves():
    result = report_writer_agent("log4j", CVES, SUMMARY)
    report = result["report"]

    assert report.startswith("# Security Vulnerability Report")
    assert "**Topic:** log4j" in report
    assert "**Total CVEs analyzed:** 2" in report
    assert "| 🔴 CRITICAL | 1 |" in report
    assert "| 🟠 HIGH | 0 |" in report
    assert "Patch Log4j immediately." in report
    assert "### 🔴 CVE-2021-44228 — Score: 10.0 (CRITICAL)" in report
    # Sévérité inconnue -> emoji neutre
    assert "### ⚪ CVE-2008-0001 — Score: N/A (N/A)" in report
    assert "[https://nvd.nist.gov/vuln/detail/CVE-2008-0001]" in report


def test_report_filename_format():
    result = report_writer_agent("apache http server", [], {})

    assert re.fullmatch(r"report_apache_http_server_\d{8}_\d{4}\.md", result["filename"])
    assert "No analysis available." in result["report"]
    assert "**Total CVEs analyzed:** 0" in result["report"]


def test_report_unscored_cve_shows_non_evalue():
    unscored = {
        "id": "CVE-2026-99999",
        "description": "Awaiting analysis.",
        "score": None,
        "severity": None,
        "published": "2026-10-04",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-99999",
    }

    report = report_writer_agent("apache", [unscored], {})["report"]

    assert "### ⚪ CVE-2026-99999 — Score: non évalué" in report
    assert "None" not in report
    assert "NONE" not in report
