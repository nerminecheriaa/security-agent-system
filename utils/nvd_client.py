import requests
import os
from typing import List, Dict

NVD_BASE_URL = os.getenv("NVD_API_BASE", "https://services.nvd.nist.gov/rest/json/cves/2.0")

def search_cves(keyword: str, max_results: int = 5) -> List[Dict]:
    """
    Recherche des CVEs sur la base NVD par mot-clé.
    Retourne une liste de CVEs avec leurs détails essentiels.
    """
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results,
    }

    try:
        response = requests.get(NVD_BASE_URL, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()

        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "N/A")

            # Score CVSS
            score = "N/A"
            severity = "N/A"
            metrics = cve.get("metrics", {})
            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]
                score = cvss.get("baseScore", "N/A")
                severity = cvss.get("baseSeverity", "N/A")
            elif "cvssMetricV2" in metrics:
                cvss = metrics["cvssMetricV2"][0]["cvssData"]
                score = cvss.get("baseScore", "N/A")
                severity = metrics["cvssMetricV2"][0].get("baseSeverity", "N/A")

            # Description
            descriptions = cve.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d["lang"] == "en"),
                "No description available"
            )

            # Date de publication
            published = cve.get("published", "N/A")[:10]

            cves.append({
                "id": cve_id,
                "description": description,
                "score": score,
                "severity": severity,
                "published": published,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            })

        return cves

    except requests.RequestException as e:
        return [{"error": f"NVD API error: {str(e)}"}]