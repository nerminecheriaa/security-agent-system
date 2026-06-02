from utils.nvd_client import search_cves
from typing import TypedDict

class ResearcherOutput(TypedDict):
    keyword: str
    cves: list
    count: int

def researcher_agent(keyword: str, max_results: int = 5) -> ResearcherOutput:
    """
    Agent 1 : Recherche des CVEs liées au mot-clé donné.
    """
    print(f" [Researcher] Recherche CVEs pour : '{keyword}'...")
    
    cves = search_cves(keyword, max_results)
    
    # Filtre les erreurs
    valid_cves = [c for c in cves if "error" not in c]
    
    print(f" [Researcher] {len(valid_cves)} CVEs trouvées.")
    
    return {
        "keyword": keyword,
        "cves": valid_cves,
        "count": len(valid_cves)
    }