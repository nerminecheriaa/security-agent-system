import os
from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage
from dotenv import load_dotenv

load_dotenv()

_llm = None

def get_llm() -> ChatGroq:
    """
    Crée le client Groq au premier appel (pas à l'import),
    pour que l'API puisse démarrer sans clé.
    """
    global _llm
    if _llm is None:
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise RuntimeError(
                "GROQ_API_KEY is not set. Add it to your .env file (see .env.example)."
            )
        _llm = ChatGroq(
            model="llama-3.1-8b-instant",
            api_key=api_key,
            temperature=0.3
        )
    return _llm

SYSTEM_PROMPT = """You are a cybersecurity expert specialized in vulnerability analysis.
Your role is to analyze CVE data and produce a clear, structured summary.
Always respond in the same language as the user's request.
Be concise, technical, and highlight the most critical vulnerabilities."""

def summarizer_agent(keyword: str, cves: list) -> dict:
    """
    Agent 2 : Analyse et résume les CVEs trouvées via LLM.
    """
    print(f" [Summarizer] Analyse de {len(cves)} CVEs...")

    if not cves:
        return {
            "summary": "Aucune CVE trouvée pour ce mot-clé.",
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0
        }

    # Formater les CVEs pour le prompt
    cve_text = ""
    for cve in cves:
        cve_text += f"""
- ID: {cve['id']}
  Description: {cve['description']}
  CVSS Score: {cve['score']} | Severity: {cve['severity']}
  Published: {cve['published']}
  URL: {cve['url']}
"""

    # Compter par sévérité
    critical = sum(1 for c in cves if str(c.get("severity", "")).upper() == "CRITICAL")
    high = sum(1 for c in cves if str(c.get("severity", "")).upper() == "HIGH")
    medium = sum(1 for c in cves if str(c.get("severity", "")).upper() == "MEDIUM")

    user_prompt = f"""Analyze these CVEs related to '{keyword}' and provide:
1. A brief overview of the threat landscape
2. The most critical vulnerabilities to prioritize
3. General recommendations

CVE Data:
{cve_text}

Respond with a clear structured analysis."""

    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=user_prompt)
    ]

    response = get_llm().invoke(messages)

    print(f" [Summarizer] Analyse terminée.")

    return {
        "summary": response.content,
        "critical_count": critical,
        "high_count": high,
        "medium_count": medium
    }