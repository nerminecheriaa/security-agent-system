from typing import TypedDict, Annotated
from langgraph.graph import StateGraph, END
from agents.researcher import researcher_agent
from agents.summarizer import summarizer_agent
from agents.report_writer import report_writer_agent
from dotenv import load_dotenv

load_dotenv()

# ── État global partagé entre tous les agents ──────────────────────────────
class AgentState(TypedDict):
    keyword: str
    max_results: int
    cves: list
    cve_count: int
    summary: str
    critical_count: int
    high_count: int
    medium_count: int
    report: str
    filename: str
    status: str

# ── Nœuds du graphe ────────────────────────────────────────────────────────
def node_researcher(state: AgentState) -> AgentState:
    result = researcher_agent(state["keyword"], state.get("max_results", 5))
    return {
        **state,
        "cves": result["cves"],
        "cve_count": result["count"],
        "status": "researched"
    }

def node_summarizer(state: AgentState) -> AgentState:
    result = summarizer_agent(state["keyword"], state["cves"])
    return {
        **state,
        "summary": result["summary"],
        "critical_count": result["critical_count"],
        "high_count": result["high_count"],
        "medium_count": result["medium_count"],
        "status": "summarized"
    }

def node_report_writer(state: AgentState) -> AgentState:
    summary_dict = {
        "summary": state["summary"],
        "critical_count": state["critical_count"],
        "high_count": state["high_count"],
        "medium_count": state["medium_count"],
    }
    result = report_writer_agent(state["keyword"], state["cves"], summary_dict)
    return {
        **state,
        "report": result["report"],
        "filename": result["filename"],
        "status": "completed"
    }

# ── Construction du graphe ─────────────────────────────────────────────────
def build_graph():
    graph = StateGraph(AgentState)

    graph.add_node("researcher", node_researcher)
    graph.add_node("summarizer", node_summarizer)
    graph.add_node("report_writer", node_report_writer)

    graph.set_entry_point("researcher")
    graph.add_edge("researcher", "summarizer")
    graph.add_edge("summarizer", "report_writer")
    graph.add_edge("report_writer", END)

    return graph.compile()

# ── Fonction principale ────────────────────────────────────────────────────
def run_security_analysis(keyword: str, max_results: int = 5) -> AgentState:
    app = build_graph()

    initial_state = AgentState(
        keyword=keyword,
        max_results=max_results,
        cves=[],
        cve_count=0,
        summary="",
        critical_count=0,
        high_count=0,
        medium_count=0,
        report="",
        filename="",
        status="pending"
    )

    print(f"\n{'='*50}")
    print(f" Starting Security Analysis for: '{keyword}'")
    print(f"{'='*50}\n")

    result = app.invoke(initial_state)

    print(f"\n{'='*50}")
    print(f" Analysis Complete! Status: {result['status']}")
    print(f"{'='*50}\n")

    return result