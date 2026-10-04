import requests
import os
import re
from datetime import datetime, timedelta, timezone
from typing import List, Literal, Optional, TypedDict

NVD_BASE_URL = os.getenv("NVD_API_BASE", "https://services.nvd.nist.gov/rest/json/cves/2.0")

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

MAX_DAYS = 120  # Limite imposée par l'API NVD sur pubStartDate/pubEndDate
MAX_LIMIT = 50
DEFAULT_DAYS_WITH_KEYWORD = 120
DEFAULT_DAYS_WITHOUT_KEYWORD = 30

# Ordre de préférence des métriques CVSS (la plus récente d'abord)
CVSS_METRICS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")

CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.ASCII)
MAX_REFERENCES = 5


class CVE(TypedDict):
    id: str
    description: str
    score: Optional[float]
    severity: Optional[str]
    published: str
    url: str


class CVSSVector(TypedDict):
    version: Optional[str]
    vector: Optional[str]
    score: Optional[float]
    severity: Optional[str]
    source: Optional[str]
    type: Optional[str]


class Reference(TypedDict):
    url: str
    tags: List[str]


class CVEDetails(CVE):
    last_modified: Optional[str]
    vuln_status: Optional[str]
    cwes: List[str]
    cvss: List[CVSSVector]
    references: List[Reference]


class NVDError(Exception):
    """Erreur réseau ou HTTP lors d'un appel à l'API NVD."""


class CVENotFoundError(LookupError):
    """La CVE demandée n'existe pas dans la base NVD."""


def resolve_days(keyword: Optional[str], days: Optional[int]) -> int:
    """
    Fenêtre de recherche effective : 120 jours avec un mot-clé, 30 sans.
    """
    if days is not None:
        return days
    return DEFAULT_DAYS_WITH_KEYWORD if keyword and keyword.strip() else DEFAULT_DAYS_WITHOUT_KEYWORD


def no_results_message(keyword: Optional[str], days: int, severity: Optional[Severity]) -> str:
    """
    Message explicite à afficher quand la recherche ne renvoie aucune CVE.
    """
    criteria = f"mot-clé '{keyword}'" if keyword else "aucun mot-clé"
    if severity:
        criteria += f", sévérité {severity}"
    message = f"Aucune CVE publiée dans les {days} derniers jours ({criteria})."
    if severity:
        message += " Les CVE très récentes n'ont souvent pas encore de score CVSS et sont exclues par le filtre de sévérité."
    return message


def _parse_cve(cve: dict) -> CVE:
    cve_id = cve.get("id", "N/A")

    # Score CVSS : on prend la version la plus récente disponible
    score = None
    severity = None
    metrics = cve.get("metrics", {})
    for key in CVSS_METRICS:
        if metrics.get(key):
            metric = metrics[key][0]
            cvss = metric.get("cvssData", {})
            score = cvss.get("baseScore")
            # CVSS v2 : la sévérité est au niveau du metric, pas dans cvssData
            severity = cvss.get("baseSeverity") or metric.get("baseSeverity")
            break

    # Description
    descriptions = cve.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d["lang"] == "en"),
        "No description available"
    )

    return {
        "id": cve_id,
        "description": description,
        "score": score,
        "severity": severity,
        "published": cve.get("published", "N/A")[:10],
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    }


def _get(params: dict) -> dict:
    headers = {}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    try:
        response = requests.get(NVD_BASE_URL, params=params, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        # NVD renvoie la cause d'un 4xx dans l'en-tête "message"
        detail = ""
        if getattr(e, "response", None) is not None:
            detail = e.response.headers.get("message", "")
        raise NVDError(f"NVD API error: {e}" + (f" ({detail})" if detail else "")) from e


def search_cves(
    keyword: Optional[str] = None,
    days: Optional[int] = None,
    severity: Optional[Severity] = None,
    limit: int = 5,
) -> List[CVE]:
    """
    Recherche les CVEs publiées récemment sur la base NVD.

    Args:
        keyword: mot-clé recherché dans les descriptions (optionnel).
        days: fenêtre de publication en jours, de 1 à 120.
              Par défaut 120 avec un mot-clé, 30 sans.
        severity: filtre sur la sévérité CVSS v3 (LOW, MEDIUM, HIGH, CRITICAL).
        limit: nombre maximum de CVEs renvoyées, de 1 à 50.

    Returns:
        Les CVEs triées de la plus récente à la plus ancienne (liste vide si aucune).

    Raises:
        ValueError: paramètre hors bornes.
        NVDError: erreur réseau ou HTTP.
    """
    keyword = keyword.strip() if keyword else None
    days = resolve_days(keyword, days)

    if not 1 <= days <= MAX_DAYS:
        raise ValueError(f"days doit être compris entre 1 et {MAX_DAYS} (reçu : {days})")
    if not 1 <= limit <= MAX_LIMIT:
        raise ValueError(f"limit doit être compris entre 1 et {MAX_LIMIT} (reçu : {limit})")
    if severity is not None and severity not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        raise ValueError(f"severity invalide : {severity}")

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": limit,
        "noRejected": "",
    }
    if keyword:
        params["keywordSearch"] = keyword
    if severity:
        params["cvssV3Severity"] = severity

    data = _get(params)

    # L'API trie du plus ancien au plus récent et n'a pas de paramètre de tri :
    # pour obtenir les plus récentes, on relit la dernière page.
    total = data.get("totalResults", 0)
    if total > limit:
        data = _get({**params, "startIndex": total - limit})

    cves = [_parse_cve(item.get("cve", {})) for item in data.get("vulnerabilities", [])]
    cves.reverse()
    return cves


def _parse_cve_details(cve: dict) -> CVEDetails:
    # CWE : dédoublonnées, toutes sources confondues (NVD et CNA)
    cwes = []
    for weakness in cve.get("weaknesses", []):
        for d in weakness.get("description", []):
            if d.get("lang") == "en" and d.get("value") and d["value"] not in cwes:
                cwes.append(d["value"])

    # Tous les vecteurs CVSS disponibles (les métriques non CVSS, ex. ssvcV203, sont ignorées)
    cvss = []
    for key in CVSS_METRICS:
        for metric in cve.get("metrics", {}).get(key, []):
            data = metric.get("cvssData", {})
            cvss.append({
                "version": data.get("version"),
                "vector": data.get("vectorString"),
                "score": data.get("baseScore"),
                "severity": data.get("baseSeverity") or metric.get("baseSeverity"),
                "source": metric.get("source"),
                "type": metric.get("type"),
            })

    references = [
        {"url": ref["url"], "tags": ref.get("tags", [])}
        for ref in cve.get("references", [])[:MAX_REFERENCES]
        if ref.get("url")
    ]

    last_modified = cve.get("lastModified")

    return {
        **_parse_cve(cve),
        "last_modified": last_modified[:10] if last_modified else None,
        "vuln_status": cve.get("vulnStatus"),
        "cwes": cwes,
        "cvss": cvss,
        "references": references,
    }


def get_cve(cve_id: str) -> CVEDetails:
    """
    Récupère le détail d'une CVE sur la base NVD à partir de son identifiant.

    Args:
        cve_id: identifiant au format CVE-AAAA-NNNN (au moins 4 chiffres après l'année).

    Returns:
        La CVE avec ses CWE, ses vecteurs CVSS et ses premières références.

    Raises:
        ValueError: identifiant mal formé (aucun appel réseau).
        CVENotFoundError: identifiant bien formé mais absent de la base NVD.
        NVDError: erreur réseau ou HTTP.
    """
    if not CVE_ID_PATTERN.fullmatch(cve_id):
        raise ValueError(f"Identifiant CVE invalide : {cve_id!r} (format attendu : CVE-AAAA-NNNN)")

    data = _get({"cveId": cve_id})

    # NVD répond 200 avec totalResults = 0 pour un identifiant inconnu
    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        raise CVENotFoundError(f"{cve_id} introuvable dans la base NVD.")

    return _parse_cve_details(vulnerabilities[0].get("cve", {}))
