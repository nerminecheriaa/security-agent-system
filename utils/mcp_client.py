"""
Client du serveur MCP NVD (mcp_server.server), lancé en sous-processus stdio.
Seul module du projet qui parle à MCP.
"""
import asyncio
import json
import os
import sys
from typing import Any, Dict, Optional

from langchain_core.tools import BaseTool, ToolException
from langchain_mcp_adapters.client import MultiServerMCPClient

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SERVER_NAME = "nvd"
SERVER_COMMAND = sys.executable
SERVER_ARGS = ["-m", "mcp_server.server"]

# Seules variables transmises au serveur (en plus de l'environnement minimal du SDK :
# PATH, SYSTEMROOT...). GROQ_API_KEY n'en fait jamais partie.
SERVER_ENV_VARS = ("NVD_API_KEY", "NVD_API_BASE")

# Valeurs masquées dans tous les messages d'erreur
SECRET_ENV_VARS = ("NVD_API_KEY", "GROQ_API_KEY")

TOOL_TIMEOUT = 30  # secondes, lancement du sous-processus compris

_tools: Optional[Dict[str, BaseTool]] = None


class MCPToolError(Exception):
    """Échec d'un appel d'outil MCP : erreur de l'outil, du transport ou délai dépassé."""


def server_env() -> Dict[str, str]:
    env = {key: os.environ[key] for key in SERVER_ENV_VARS if os.environ.get(key)}
    # -m mcp_server.server doit fonctionner quel que soit le dossier de lancement
    env["PYTHONPATH"] = PROJECT_ROOT
    return env


def server_connection() -> dict:
    return {
        "transport": "stdio",
        "command": SERVER_COMMAND,
        "args": SERVER_ARGS,
        "cwd": PROJECT_ROOT,
        "env": server_env(),
    }


def _redact(message: str) -> str:
    for key in SECRET_ENV_VARS:
        value = os.environ.get(key)
        if value:
            message = message.replace(value, "***")
    return message


def _root_cause(error: BaseException) -> BaseException:
    # Les erreurs de transport arrivent souvent enveloppées dans un ExceptionGroup (anyio)
    while isinstance(error, BaseExceptionGroup) and error.exceptions:
        error = error.exceptions[0]
    return error


async def _get_tools() -> Dict[str, BaseTool]:
    # La liste des outils est mise en cache ; chaque appel d'outil ouvre sa propre session
    global _tools
    if _tools is None:
        client = MultiServerMCPClient({SERVER_NAME: server_connection()})
        _tools = {tool.name: tool for tool in await client.get_tools()}
    return _tools


async def _invoke(name: str, arguments: dict) -> Any:
    tools = await _get_tools()
    if name not in tools:
        raise MCPToolError(f"Outil MCP inconnu : {name}")

    content = await tools[name].ainvoke(arguments)

    # Le serveur renvoie un seul bloc texte JSON par appel
    if isinstance(content, list) and len(content) == 1:
        content = content[0]
    if not isinstance(content, str):
        raise MCPToolError(f"Réponse inattendue de l'outil MCP {name}")
    try:
        return json.loads(content)
    except json.JSONDecodeError as e:
        raise MCPToolError(f"Réponse non JSON de l'outil MCP {name}") from e


async def call_tool(name: str, arguments: dict, timeout: float = TOOL_TIMEOUT) -> Any:
    """
    Appelle un outil du serveur MCP NVD et renvoie sa réponse JSON décodée.

    Raises:
        MCPToolError: erreur renvoyée par l'outil (paramètre invalide, erreur NVD...),
            serveur impossible à lancer, erreur de transport ou délai dépassé.
            Le message ne contient ni trace ni clé API.
    """
    try:
        return await asyncio.wait_for(_invoke(name, arguments), timeout)
    except MCPToolError:
        raise
    except ToolException as e:
        raise MCPToolError(_redact(str(e))) from None
    except asyncio.TimeoutError:
        raise MCPToolError(f"Délai dépassé ({timeout:g} s) pour l'outil MCP {name}") from None
    except Exception as e:
        cause = _root_cause(e)
        detail = _redact(str(cause)) or type(cause).__name__
        raise MCPToolError(f"Serveur MCP indisponible : {detail}") from None
