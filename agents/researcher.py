from utils.nvd_client import NVDError, Severity, no_results_message, resolve_days, search_cves
from typing import Optional, TypedDict

class ResearcherOutput(TypedDict):
    keyword: Optional[str]
    cves: list
    count: int
    message: Optional[str]

def researcher_agent(
    keyword: Optional[str] = None,
    max_results: int = 5,
    days: Optional[int] = None,
    severity: Optional[Severity] = None,
) -> ResearcherOutput:
    """
    Agent 1 : Recherche les CVEs récentes liées au mot-clé donné.
    """
    days = resolve_days(keyword, days)
    print(f" [Researcher] Recherche CVEs pour : '{keyword or '*'}' ({days} derniers jours)...")

    message = None
    try:
        cves = search_cves(keyword, days=days, severity=severity, limit=max_results)
    except NVDError as e:
        cves = []
        message = str(e)

    if not cves and message is None:
        message = no_results_message(keyword, days, severity)

    print(f" [Researcher] {len(cves)} CVEs trouvées." + (f" {message}" if message else ""))

    return {
        "keyword": keyword,
        "cves": cves,
        "count": len(cves),
        "message": message
    }
