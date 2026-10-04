import asyncio
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from langchain_core.tools import ToolException

from utils import mcp_client
# Référence capturée à l'import, avant que conftest ne remplace call_tool par l'appel en mémoire
from utils.mcp_client import MCPToolError, call_tool

LOG4SHELL = {"totalResults": 1, "vulnerabilities": [{"cve": {
    "id": "CVE-2021-44228",
    "published": "2021-12-10T10:15:09.143",
    "descriptions": [{"lang": "en", "value": "Apache Log4j2 JNDI RCE."}],
    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}]},
}}]}


@pytest.fixture(autouse=True)
def isolated_client(monkeypatch):
    # Pas de cache d'outils partagé entre les tests, ni de variables NVD de la machine
    monkeypatch.setattr(mcp_client, "_tools", None)
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delenv("NVD_API_BASE", raising=False)


@pytest.fixture
def fake_nvd(monkeypatch):
    """
    Faux NVD en HTTP local, utilisé par le vrai sous-processus via NVD_API_BASE.
    """
    state = {"delay": 0, "requests": []}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            state["requests"].append(self.path)
            time.sleep(state["delay"])
            body = json.dumps(LOG4SHELL).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setenv("NVD_API_BASE", f"http://127.0.0.1:{server.server_port}/")
    yield state
    server.shutdown()
    server.server_close()


def run(coro, timeout=60):
    return asyncio.run(asyncio.wait_for(coro, timeout))


def test_call_tool_through_stdio_subprocess(fake_nvd):
    result = run(call_tool("search_cves", {"keyword": "log4j", "limit": 1}))

    assert result["count"] == 1
    assert result["message"] is None
    assert result["cves"][0]["id"] == "CVE-2021-44228"
    assert "keywordSearch=log4j" in fake_nvd["requests"][0]


def test_tool_error_becomes_explicit_message():
    # Validation des bornes côté serveur : aucun accès réseau
    with pytest.raises(MCPToolError) as exc_info:
        run(call_tool("search_cves", {"keyword": "apache", "days": 999}))

    message = str(exc_info.value)
    assert "Error executing tool search_cves" in message
    assert "less than or equal to 120" in message
    assert "Traceback" not in message


def test_timeout_becomes_explicit_message(fake_nvd):
    fake_nvd["delay"] = 5
    start = time.monotonic()

    with pytest.raises(MCPToolError, match=r"Délai dépassé \(2 s\) pour l'outil MCP search_cves"):
        run(call_tool("search_cves", {"keyword": "apache"}, timeout=2))

    assert time.monotonic() - start < 10


def test_server_that_cannot_start(monkeypatch):
    monkeypatch.setattr(mcp_client, "SERVER_COMMAND", "D:/does-not-exist/python.exe")

    with pytest.raises(MCPToolError, match="Serveur MCP indisponible"):
        run(call_tool("search_cves", {"keyword": "apache"}, timeout=20))


def test_unknown_tool(monkeypatch):
    async def fake_get_tools():
        return {}

    monkeypatch.setattr(mcp_client, "_get_tools", fake_get_tools)

    with pytest.raises(MCPToolError, match="Outil MCP inconnu : nope"):
        run(call_tool("nope", {}))


def test_secrets_are_redacted_from_error_messages(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "nvd-secret-value")
    monkeypatch.setenv("GROQ_API_KEY", "groq-secret-value")

    async def failing_invoke(name, arguments):
        raise ToolException("boom nvd-secret-value groq-secret-value")

    monkeypatch.setattr(mcp_client, "_invoke", failing_invoke)

    with pytest.raises(MCPToolError) as exc_info:
        run(call_tool("search_cves", {}))

    assert str(exc_info.value) == "boom *** ***"


def test_subprocess_env_never_contains_groq_key(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "groq-secret-value")
    monkeypatch.setenv("NVD_API_KEY", "nvd-key")
    monkeypatch.setenv("NVD_API_BASE", "http://127.0.0.1:9/")
    monkeypatch.setenv("UNRELATED_SECRET", "x")

    connection = mcp_client.server_connection()

    assert connection["env"] == {
        "NVD_API_KEY": "nvd-key",
        "NVD_API_BASE": "http://127.0.0.1:9/",
        "PYTHONPATH": mcp_client.PROJECT_ROOT,
    }
    assert "groq-secret-value" not in json.dumps(connection)
    assert connection["cwd"] == mcp_client.PROJECT_ROOT
    assert connection["args"] == ["-m", "mcp_server.server"]


def test_subprocess_env_without_nvd_variables():
    assert mcp_client.server_env() == {"PYTHONPATH": mcp_client.PROJECT_ROOT}
