from utils import mcp_client
from utils.mcp_client import MCPToolError
from utils.nvd_client import Severity, resolve_days
from typing import Optional, TypedDict

class ResearcherOutput(TypedDict):
    keyword: Optional[str]
    cves: list
    count: int
    message: Optional[str]

async def researcher_agent(
    keyword: Optional[str] = None,
    max_results: int = 5,
    days: Optional[int] = None,
    severity: Optional[Severity] = None,
) -> ResearcherOutput:
    """
    Agent 1 : Recherche les CVEs récentes liées au mot-clé donné,
    via l'outil search_cves du serveur MCP NVD.
    """
    days = resolve_days(keyword, days)
    print(f" [Researcher] Recherche CVEs pour : '{keyword or '*'}' ({days} derniers jours)...")

    arguments = {"keyword": keyword, "days": days, "severity": severity, "limit": max_results}
    try:
        result = await mcp_client.call_tool(
            "search_cves", {k: v for k, v in arguments.items() if v is not None}
        )
        cves = result["cves"]
        count = result["count"]
        message = result["message"]
    except MCPToolError as e:
        cves = []
        count = 0
        message = str(e)

    print(f" [Researcher] {len(cves)} CVEs trouvées." + (f" {message}" if message else ""))

    return {
        "keyword": keyword,
        "cves": cves,
        "count": count,
        "message": message
    }
