import pytest

import agents.summarizer
# Référence capturée à l'import, avant que conftest ne remplace get_llm
from agents.summarizer import get_llm, summarizer_agent


def test_summarizer_unscored_cve_shows_non_evalue(no_network):
    cves = [
        {
            "id": "CVE-2026-99999",
            "description": "Awaiting analysis.",
            "score": None,
            "severity": None,
            "published": "2026-10-04",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-99999",
        },
        {
            "id": "CVE-2021-44228",
            "description": "Apache Log4j2 JNDI RCE.",
            "score": 10.0,
            "severity": "CRITICAL",
            "published": "2021-12-10",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        },
    ]

    result = summarizer_agent("apache", cves)

    prompt = no_network.invoke.call_args[0][0][1].content
    assert "CVSS Score: non évalué | Severity: non évalué" in prompt
    assert "None" not in prompt
    # La CVE non évaluée n'est comptée dans aucune sévérité
    assert result["critical_count"] == 1
    assert result["high_count"] == 0
    assert result["medium_count"] == 0


@pytest.mark.parametrize("env_value, expected", [
    (None, "openai/gpt-oss-20b"),
    ("", "openai/gpt-oss-20b"),
    ("openai/gpt-oss-120b","openai/gpt-oss-120b"),
])
def test_get_llm_model_from_env(monkeypatch, env_value, expected):
    monkeypatch.setenv("GROQ_API_KEY", "dummy")
    if env_value is None:
        monkeypatch.delenv("GROQ_MODEL", raising=False)
    else:
        monkeypatch.setenv("GROQ_MODEL", env_value)
    # Réinitialise le client mis en cache (aucun appel réseau à la construction)
    monkeypatch.setattr(agents.summarizer, "_llm", None)

    assert get_llm().model_name == expected
