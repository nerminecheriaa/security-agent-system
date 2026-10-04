from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Literal, Optional
import uuid
import os
from dotenv import load_dotenv
from orchestrator import run_security_analysis

load_dotenv()

app = FastAPI(
    title=" Security Agent System",
    description="Multi-agent CVE analysis powered by LangGraph + Groq",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Stockage en mémoire des résultats (simple, pas besoin de DB) ───────────
results_store: dict = {}

# ── Schémas Pydantic ───────────────────────────────────────────────────────
class AnalysisRequest(BaseModel):
    keyword: str = Field(..., min_length=2, max_length=100, example="apache")
    max_results: Optional[int] = Field(default=5, ge=1, le=20)
    days: Optional[int] = Field(
        default=None, ge=1, le=120,
        description="Fenêtre de publication en jours (défaut : 120 avec un mot-clé)"
    )
    severity: Optional[Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]] = None

class AnalysisResponse(BaseModel):
    job_id: str
    keyword: str
    status: str
    cve_count: int
    message: Optional[str] = None
    critical_count: int
    high_count: int
    medium_count: int
    report: str
    filename: str

# ── Endpoints ──────────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {
        "message": " Security Agent System is running!",
        "docs": "/docs",
        "endpoints": ["/analyze", "/results/{job_id}", "/health"]
    }

@app.get("/health")
def health():
    return {"status": "healthy", "agents": ["researcher", "summarizer", "report_writer"]}

@app.post("/analyze", response_model=AnalysisResponse)
def analyze(request: AnalysisRequest):
    """
    Lance une analyse complète multi-agent pour un mot-clé donné.
    Enchaîne : Researcher → Summarizer → Report Writer
    """
    job_id = str(uuid.uuid4())[:8]

    try:
        result = run_security_analysis(
            request.keyword,
            request.max_results,
            days=request.days,
            severity=request.severity,
        )

        response = AnalysisResponse(
            job_id=job_id,
            keyword=result["keyword"],
            status=result["status"],
            cve_count=result["cve_count"],
            message=result.get("message"),
            critical_count=result["critical_count"],
            high_count=result["high_count"],
            medium_count=result["medium_count"],
            report=result["report"],
            filename=result["filename"]
        )

        # Sauvegarde en mémoire
        results_store[job_id] = response.model_dump()

        return response

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.get("/results/{job_id}")
def get_result(job_id: str):
    """
    Récupère le résultat d'une analyse précédente par son job_id.
    """
    if job_id not in results_store:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found.")
    return results_store[job_id]

@app.get("/history")
def get_history():
    """
    Retourne la liste de toutes les analyses effectuées.
    """
    return {
        "total": len(results_store),
        "jobs": [
            {
                "job_id": jid,
                "keyword": r["keyword"],
                "status": r["status"],
                "cve_count": r["cve_count"]
            }
            for jid, r in results_store.items()
        ]
    }