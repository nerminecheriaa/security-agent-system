import asyncio
import json
import os
import sys
from unittest.mock import MagicMock

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import get_default_environment, stdio_client
from mcp.server.fastmcp.exceptions import ToolError

from mcp_server.server import mcp

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LOG4SHELL = {"totalResults": 1, "vulnerabilities": [{"cve": {
    "id": "CVE-2021-44228",
    "published": "2021-12-10T10:15:09.143",
    "lastModified": "2026-08-11T19:33:44.513",
    "vulnStatus": "Analyzed",
    "descriptions": [{"lang": "en", "value": "Apache Log4j2 JNDI RCE."}],
    "metrics": {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {
        "version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "baseScore": 10.0, "baseSeverity": "CRITICAL"}}]},
    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-502"}]}],
    "references": [{"url": "https://example.org/advisory", "tags": ["Vendor Advisory"]}],
}}]}

EMPTY = {"totalResults": 0, "vulnerabilities": []}


def mock_get(monkeypatch, *responses):
    calls = []

    def fake_get(url, params=None, headers=None, timeout=None):
        calls.append({"params": params, "headers": headers})
        response = MagicMock()
        response.json.return_value = responses[len(calls) - 1]
        response.raise_for_status.return_value = None
        return response

    monkeypatch.setattr("utils.nvd_client.requests.get", fake_get)
    return calls


def call_tool(name, arguments):
    """
    Appelle un outil en mémoire. Renvoie (contenu texte décodé, résultat structuré).
    """
    content, structured = asyncio.run(mcp.call_tool(name, arguments))
    # Un seul bloc JSON : c'est ce que reçoit un client qui ignore structuredContent
    assert len(content) == 1
    return json.loads(content[0].text), structured


def tool_schemas():
    return {tool.name: tool.inputSchema for tool in asyncio.run(mcp.list_tools())}


# ── (a) Outils appelés en mémoire ──────────────────────────────────────────
def test_search_cves_tool_returns_cves(monkeypatch):
    calls = mock_get(monkeypatch, LOG4SHELL)

    text, structured = call_tool("search_cves", {"keyword": "log4j", "days": 7, "severity": "CRITICAL", "limit": 3})

    params = calls[0]["params"]
    assert params["keywordSearch"] == "log4j"
    assert params["cvssV3Severity"] == "CRITICAL"
    assert params["resultsPerPage"] == 3
    assert text == structured
    assert text["count"] == 1
    assert text["message"] is None
    assert text["cves"][0]["id"] == "CVE-2021-44228"
    assert text["cves"][0]["score"] == 10.0


def test_search_cves_tool_explicit_message_when_empty(monkeypatch):
    mock_get(monkeypatch, EMPTY)

    text, _ = call_tool("search_cves", {"keyword": "  unknownproduct ", "severity": "HIGH"})

    assert text["count"] == 0
    assert text["cves"] == []
    assert "Aucune CVE" in text["message"]
    assert "120 derniers jours" in text["message"]
    assert "'unknownproduct'" in text["message"]


@pytest.mark.parametrize("arguments", [
    {"days": 0},
    {"days": 999},
    {"limit": 51},
    {"severity": "URGENT"},
])
def test_search_cves_tool_rejects_out_of_range_arguments(monkeypatch, arguments):
    calls = mock_get(monkeypatch, EMPTY)

    with pytest.raises(ToolError, match="Error executing tool search_cves"):
        asyncio.run(mcp.call_tool("search_cves", arguments))

    assert calls == []


def test_get_cve_details_tool_found(monkeypatch):
    calls = mock_get(monkeypatch, LOG4SHELL)

    text, structured = call_tool("get_cve_details", {"cve_id": "CVE-2021-44228"})

    assert calls[0]["params"] == {"cveId": "CVE-2021-44228"}
    assert text == structured
    assert text["id"] == "CVE-2021-44228"
    assert text["vuln_status"] == "Analyzed"
    assert text["cwes"] == ["CWE-502"]
    assert text["cvss"][0]["vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert text["references"] == [{"url": "https://example.org/advisory", "tags": ["Vendor Advisory"]}]


def test_get_cve_details_tool_normalizes_lowercase_id(monkeypatch):
    calls = mock_get(monkeypatch, LOG4SHELL)

    call_tool("get_cve_details", {"cve_id": "  cve-2021-44228 "})

    assert calls[0]["params"] == {"cveId": "CVE-2021-44228"}


def test_get_cve_details_tool_not_found(monkeypatch):
    mock_get(monkeypatch, EMPTY)

    with pytest.raises(ToolError, match="CVE-2099-99999 introuvable dans la base NVD"):
        asyncio.run(mcp.call_tool("get_cve_details", {"cve_id": "CVE-2099-99999"}))


def test_get_cve_details_tool_invalid_id(monkeypatch):
    calls = mock_get(monkeypatch, LOG4SHELL)

    with pytest.raises(ToolError, match="Identifiant CVE invalide"):
        asyncio.run(mcp.call_tool("get_cve_details", {"cve_id": "log4shell"}))

    assert calls == []


def test_tool_error_does_not_leak_api_key(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "secret-key-value")
    mock_get(monkeypatch, EMPTY)

    with pytest.raises(ToolError) as exc_info:
        asyncio.run(mcp.call_tool("get_cve_details", {"cve_id": "CVE-2099-99999"}))

    assert "secret-key-value" not in str(exc_info.value)
    assert "Traceback" not in str(exc_info.value)


# ── (b) Schéma exposé aux clients MCP ──────────────────────────────────────
def test_tool_names():
    assert set(tool_schemas()) == {"search_cves", "get_cve_details"}


def test_search_cves_schema_exposes_bounds_and_enum():
    props = tool_schemas()["search_cves"]["properties"]

    days = next(s for s in props["days"]["anyOf"] if s["type"] == "integer")
    assert (days["minimum"], days["maximum"]) == (1, 120)
    assert (props["limit"]["minimum"], props["limit"]["maximum"], props["limit"]["default"]) == (1, 50, 5)
    severity = next(s for s in props["severity"]["anyOf"] if s["type"] == "string")
    assert severity["enum"] == ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert props["keyword"]["default"] is None
    assert all(props[name].get("description") for name in ("keyword", "days", "severity", "limit"))
    assert tool_schemas()["search_cves"].get("required", []) == []


def test_get_cve_details_schema_requires_cve_id():
    schema = tool_schemas()["get_cve_details"]

    assert schema["required"] == ["cve_id"]
    assert schema["properties"]["cve_id"]["type"] == "string"
    assert schema["properties"]["cve_id"]["description"]


# ── (c) Intégration : vrai sous-processus en stdio ─────────────────────────
async def run_stdio_session():
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "mcp_server.server"],
        cwd=PROJECT_ROOT,
        # Port local fermé : un appel NVD non prévu échouerait immédiatement, sans sortir sur Internet
        env={**get_default_environment(), "NVD_API_BASE": "http://127.0.0.1:9/"},
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            result = await session.call_tool("search_cves", {"keyword": "apache", "days": 999})
            return tools, result


def test_stdio_server_lists_tools_and_reports_errors():
    tools, result = asyncio.run(asyncio.wait_for(run_stdio_session(), timeout=30))

    assert {tool.name for tool in tools.tools} == {"search_cves", "get_cve_details"}
    assert result.isError is True
    message = result.content[0].text
    assert "Error executing tool search_cves" in message
    assert "less than or equal to 120" in message
    assert "Traceback" not in message


# ── Chargement de .env par le serveur ──────────────────────────────────────
def test_server_loads_only_nvd_variables_from_dotenv(monkeypatch, tmp_path):
    from mcp_server.server import load_nvd_env

    dotenv = tmp_path / ".env"
    dotenv.write_text("GROQ_API_KEY=groq-secret\nNVD_API_KEY=nvd-from-file\nOTHER=x\n")
    for key in ("GROQ_API_KEY", "NVD_API_KEY", "NVD_API_BASE", "OTHER"):
        monkeypatch.delenv(key, raising=False)

    load_nvd_env(str(dotenv))

    assert os.environ.get("NVD_API_KEY") == "nvd-from-file"
    assert "GROQ_API_KEY" not in os.environ
    assert "OTHER" not in os.environ


def test_server_keeps_nvd_variables_passed_by_client(monkeypatch, tmp_path):
    from mcp_server.server import load_nvd_env

    dotenv = tmp_path / ".env"
    dotenv.write_text("NVD_API_KEY=nvd-from-file\n")
    monkeypatch.setenv("NVD_API_KEY", "nvd-from-client")

    load_nvd_env(str(dotenv))

    assert os.environ["NVD_API_KEY"] == "nvd-from-client"
