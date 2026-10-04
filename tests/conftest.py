import json
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from mcp_server.server import mcp
from utils.mcp_client import MCPToolError


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """
    Bloque tout appel réseau réel : NVD (requests.get) et Groq (get_llm).
    Les tests qui ont besoin d'une réponse NVD remplacent requests.get eux-mêmes.
    """
    def blocked_get(*args, **kwargs):
        raise AssertionError(f"Unmocked network call: requests.get{args}")

    monkeypatch.setattr("utils.nvd_client.requests.get", blocked_get)

    fake_llm = MagicMock()
    fake_llm.invoke.return_value = MagicMock(content="Mocked AI analysis.")
    monkeypatch.setattr("agents.summarizer.get_llm", lambda: fake_llm)
    return fake_llm


@pytest.fixture(autouse=True)
def mcp_in_memory(monkeypatch):
    """
    Remplace utils.mcp_client.call_tool par un appel en mémoire aux outils du serveur :
    pas de sous-processus, et le NVD simulé (requests.get) s'applique.
    Les tests du vrai client importent call_tool avant que cette fixture ne s'applique.
    """
    async def call_tool(name, arguments, timeout=None):
        try:
            content, _ = await mcp.call_tool(name, arguments)
        except ToolError as e:
            raise MCPToolError(str(e)) from None
        return json.loads(content[0].text)

    monkeypatch.setattr("utils.mcp_client.call_tool", call_tool)
