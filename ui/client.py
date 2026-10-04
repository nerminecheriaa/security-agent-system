"""
Client HTTP de l'API Security Agent System, utilisé par l'interface Streamlit.
Toutes les erreurs deviennent une APIError au message court, sans trace.
"""
import os
import re
from typing import Optional

import requests

API_URL = os.getenv("API_URL", "http://localhost:8000").rstrip("/")

ANALYZE_TIMEOUT = 60  # secondes : l'analyse enchaîne NVD et le LLM
DEFAULT_TIMEOUT = 10
CONNECT_TIMEOUT = 5

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

# Clés Groq (gsk_...) et valeurs des clés présentes dans l'environnement de l'interface
SECRET_PATTERN = re.compile(r"gsk_[A-Za-z0-9]+")
SECRET_ENV_VARS = ("GROQ_API_KEY", "NVD_API_KEY")


class APIError(Exception):
    """Erreur affichable telle quelle à l'utilisateur."""


def build_analyze_payload(
    keyword: str,
    max_results: int,
    days: Optional[int] = None,
    severity: Optional[str] = None,
) -> dict:
    """
    Corps de POST /analyze. days et severity ne sont envoyés que s'ils sont choisis,
    pour garder les valeurs par défaut de l'API.
    """
    payload = {"keyword": keyword.strip(), "max_results": max_results}
    if days is not None:
        payload["days"] = days
    if severity in SEVERITIES:
        payload["severity"] = severity
    return payload


def _redact(text: str) -> str:
    text = SECRET_PATTERN.sub("***", text)
    for key in SECRET_ENV_VARS:
        value = os.getenv(key)
        if value:
            text = text.replace(value, "***")
    return text


def _validation_message(detail) -> str:
    # Format FastAPI : [{"loc": ["body", "days"], "msg": "...", ...}]
    if not isinstance(detail, list):
        return f"Paramètres invalides : {detail}"
    errors = []
    for error in detail:
        field = ".".join(str(part) for part in error.get("loc", []) if part != "body")
        errors.append(f"{field or 'requête'} : {error.get('msg', 'valeur invalide')}")
    return "Paramètres invalides — " + " ; ".join(errors)


def _error_message(response: requests.Response) -> str:
    try:
        detail = response.json().get("detail")
    except ValueError:
        detail = None

    if response.status_code == 422:
        return _validation_message(detail)
    if response.status_code == 404:
        return f"Introuvable : {detail or 'ressource inconnue'}"
    if response.status_code >= 500:
        return f"Erreur de l'API ({response.status_code}) : {detail or 'erreur interne'}"
    return f"Réponse inattendue de l'API ({response.status_code})"


def _request(method: str, path: str, timeout: float, **kwargs) -> dict:
    url = f"{API_URL}{path}"
    try:
        response = requests.request(method, url, timeout=(CONNECT_TIMEOUT, timeout), **kwargs)
    except requests.Timeout:
        raise APIError(f"Délai dépassé : l'API n'a pas répondu en {timeout:g} s.") from None
    except requests.ConnectionError:
        raise APIError(f"API injoignable à {API_URL}. Vérifiez qu'elle est lancée.") from None
    except requests.RequestException as e:
        raise APIError(_redact(f"Erreur réseau : {type(e).__name__}")) from None

    if not response.ok:
        raise APIError(_redact(_error_message(response)))
    try:
        return response.json()
    except ValueError:
        raise APIError("Réponse de l'API illisible (JSON invalide).") from None


def analyze(keyword: str, max_results: int, days: Optional[int] = None, severity: Optional[str] = None) -> dict:
    payload = build_analyze_payload(keyword, max_results, days, severity)
    return _request("POST", "/analyze", ANALYZE_TIMEOUT, json=payload)


def get_history() -> list:
    return _request("GET", "/history", DEFAULT_TIMEOUT).get("jobs", [])


def get_result(job_id: str) -> dict:
    return _request("GET", f"/results/{job_id}", DEFAULT_TIMEOUT)
