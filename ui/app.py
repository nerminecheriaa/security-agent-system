"""
Interface Streamlit du Security Agent System.
Appelle l'API FastAPI en HTTP (voir ui/client.py) ; l'URL vient de API_URL.

Lancement : python -m streamlit run ui/app.py
"""
import os
import sys

import streamlit as st

# Rend le package ui importable quel que soit le dossier de lancement
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui import client  # noqa: E402

SEVERITY_OPTIONS = ["Toutes", *client.SEVERITIES]


# ── État de la session ─────────────────────────────────────────────────────
def init_state():
    st.session_state.setdefault("result", None)
    st.session_state.setdefault("error", None)
    st.session_state.setdefault("history", None)


def refresh_history():
    try:
        st.session_state.history = client.get_history()
    except client.APIError:
        # L'historique est secondaire : l'erreur principale s'affiche ailleurs
        st.session_state.history = None


def run_analysis(keyword, max_results, days, severity):
    with st.spinner(f"Analyse de « {keyword} » en cours (jusqu'à {client.ANALYZE_TIMEOUT} s)..."):
        try:
            st.session_state.result = client.analyze(keyword, max_results, days, severity)
            st.session_state.error = None
        except client.APIError as e:
            st.session_state.error = str(e)
    refresh_history()


def load_result(job_id):
    try:
        st.session_state.result = client.get_result(job_id)
        st.session_state.error = None
    except client.APIError as e:
        st.session_state.error = str(e)


# ── Barre latérale : historique ────────────────────────────────────────────
def render_history():
    st.sidebar.header("Historique")
    if st.sidebar.button("Rafraîchir", use_container_width=True):
        refresh_history()

    jobs = st.session_state.history
    if jobs is None:
        st.sidebar.caption(f"Historique indisponible (API : {client.API_URL}).")
        return
    if not jobs:
        st.sidebar.caption("Aucune analyse pour le moment.")
        return

    # Les plus récentes en premier
    for job in reversed(jobs):
        label = f"{job['keyword']} — {job['cve_count']} CVE"
        if st.sidebar.button(label, key=f"job_{job['job_id']}", use_container_width=True):
            load_result(job["job_id"])


# ── Formulaire ─────────────────────────────────────────────────────────────
def render_form():
    keyword = st.text_input("Mot-clé *", placeholder="ex. apache, openssl, log4j")

    col_days, col_severity, col_results = st.columns(3)
    with col_days:
        limit_days = st.checkbox("Limiter la période", help="Sinon : 120 derniers jours (défaut de l'API)")
        days = st.slider("Jours", min_value=1, max_value=120, value=30, disabled=not limit_days)
    with col_severity:
        severity = st.selectbox("Sévérité", SEVERITY_OPTIONS)
    with col_results:
        max_results = st.number_input("Nombre de résultats", min_value=1, max_value=20, value=5, step=1)

    if st.button("Lancer l'analyse", type="primary"):
        if not keyword.strip():
            st.session_state.error = "Le mot-clé est obligatoire."
            return
        run_analysis(
            keyword.strip(),
            int(max_results),
            days if limit_days else None,
            severity if severity != "Toutes" else None,
        )


# ── Résultat ───────────────────────────────────────────────────────────────
def render_result(result):
    st.subheader(f"Résultat : {result['keyword']}")
    st.caption(f"{result['cve_count']} CVE analysées · analyse {result['job_id']}")

    col_critical, col_high, col_medium = st.columns(3)
    col_critical.metric("🔴 Critique", result["critical_count"])
    col_high.metric("🟠 Élevée", result["high_count"])
    col_medium.metric("🟡 Moyenne", result["medium_count"])

    if result.get("message"):
        st.warning(result["message"])

    st.download_button(
        "Télécharger le rapport (.md)",
        data=result["report"],
        file_name=result["filename"],
        mime="text/markdown",
    )
    st.divider()
    st.markdown(result["report"])


# ── Page ───────────────────────────────────────────────────────────────────
def main():
    st.set_page_config(page_title="Security Agent System", page_icon="🛡️", layout="wide")
    init_state()
    if st.session_state.history is None:
        refresh_history()

    st.title("🛡️ Security Agent System")
    st.caption("Analyse des CVE récentes (NVD) résumée par IA")

    # Le formulaire d'abord : une analyse lancée rafraîchit l'historique avant son affichage
    render_form()
    render_history()

    if st.session_state.error:
        st.error(st.session_state.error)
    if st.session_state.result:
        render_result(st.session_state.result)


main()
