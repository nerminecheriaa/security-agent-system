"""
Serveur MCP exposant la base NVD : search_cves et get_cve_details.

Lancement (transport stdio) : python -m mcp_server.server
stdout est réservé au protocole MCP : les logs partent sur stderr.
"""
import logging
import os
from typing import Annotated, List, Optional, TypedDict

import anyio
from dotenv import dotenv_values
from mcp.server.fastmcp import FastMCP
from pydantic import Field

from utils import nvd_client
from utils.nvd_client import CVE, MAX_DAYS, MAX_LIMIT, CVEDetails, Severity, no_results_message, resolve_days

DOTENV_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
NVD_ENV_VARS = ("NVD_API_KEY", "NVD_API_BASE")


def load_nvd_env(path: str = DOTENV_PATH) -> None:
    """
    Lit uniquement les variables NVD depuis .env (lancement autonome du serveur).
    Les autres secrets du fichier, dont GROQ_API_KEY, ne sont jamais chargés ;
    les variables déjà transmises par le client MCP sont prioritaires.
    """
    for key, value in dotenv_values(path).items():
        if key in NVD_ENV_VARS and value and not os.environ.get(key):
            os.environ[key] = value


load_nvd_env()

logger = logging.getLogger(__name__)

mcp = FastMCP("nvd")


class SearchResult(TypedDict):
    count: int
    cves: List[CVE]
    message: Optional[str]


@mcp.tool()
async def search_cves(
    keyword: Annotated[Optional[str], Field(
        description="Word or phrase searched in CVE descriptions (e.g. 'apache', 'openssl'). "
                    "Omit it to list the latest CVEs regardless of topic."
    )] = None,
    days: Annotated[Optional[int], Field(
        ge=1, le=MAX_DAYS,
        description="Publication window in days, counted back from now. "
                    "Defaults to 120 with a keyword, 30 without."
    )] = None,
    severity: Annotated[Optional[Severity], Field(
        description="Keep only CVEs with this CVSS v3 severity. Very recent CVEs often "
                    "have no score yet and are excluded by this filter."
    )] = None,
    limit: Annotated[int, Field(
        ge=1, le=MAX_LIMIT,
        description="Maximum number of CVEs returned."
    )] = 5,
) -> SearchResult:
    """
    Search the NVD (National Vulnerability Database) for recently published CVEs.

    Returns an object with:
    - count: number of CVEs returned;
    - cves: the matching CVEs, most recent first. Each CVE has: id, description (English),
      CVSS base score and severity (null when NVD has not scored it yet), publication
      date (YYYY-MM-DD) and the NVD page url;
    - message: explanation when no CVE matches (window and filters used), otherwise null.
    Use get_cve_details to get CWEs, CVSS vectors and references for one CVE.
    """
    logger.info("search_cves keyword=%r days=%s severity=%s limit=%s", keyword, days, severity, limit)
    cves = await anyio.to_thread.run_sync(
        lambda: nvd_client.search_cves(keyword, days=days, severity=severity, limit=limit)
    )

    # Un résultat vide doit rester explicite pour le LLM (le client MCP le transmettrait comme "")
    message = None
    if not cves:
        keyword = keyword.strip() if keyword else None
        message = no_results_message(keyword, resolve_days(keyword, days), severity)

    return {"count": len(cves), "cves": cves, "message": message}


@mcp.tool()
async def get_cve_details(
    cve_id: Annotated[str, Field(
        description="CVE identifier such as 'CVE-2021-44228' (case-insensitive)."
    )],
) -> CVEDetails:
    """
    Get the full NVD record of one CVE from its identifier.

    Returns the same fields as each CVE of search_cves plus: last_modified date, vuln_status
    (e.g. 'Analyzed', 'Awaiting Analysis', 'Rejected'), CWE weakness ids, every
    available CVSS entry (version, vector, score, severity, source, Primary/Secondary
    type) and the first 5 references (url and tags such as 'Patch' or 'Exploit').
    Fails with an explicit error when the identifier is malformed or unknown to NVD.
    """
    cve_id = cve_id.strip().upper()
    logger.info("get_cve_details cve_id=%s", cve_id)
    return await anyio.to_thread.run_sync(nvd_client.get_cve, cve_id)


if __name__ == "__main__":
    mcp.run(transport="stdio")
