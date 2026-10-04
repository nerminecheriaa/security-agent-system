from unittest.mock import MagicMock

import pytest


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """
    Bloque tout appel réseau réel : NVD (requests.get) et Groq (get_llm).
    Les tests qui ont besoin d'une réponse NVD remplacent requests.get eux-mêmes.
    """
    def blocked_get(*args, **kwargs):
        raise AssertionError(f"Unmocked network call: requests.get{args}")

    monkeypatch.setattr("utils.nvd_client.requests.get", blocked_get)

    fake_llm = MagicMock()
    fake_llm.invoke.return_value = MagicMock(content="Mocked AI analysis.")
    monkeypatch.setattr("agents.summarizer.get_llm", lambda: fake_llm)
    return fake_llm
