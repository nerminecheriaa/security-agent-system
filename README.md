#  Security Agent System

> Multi-agent AI pipeline for automated CVE vulnerability analysis

Built with **LangGraph**, **Groq (LLaMA 3.1)**, **FastAPI**, and the **NVD API**.

##  Architecture
User Query
↓
LangGraph Orchestrator
↓           ↓            ↓
Researcher   Summarizer   Report Writer
(NVD API)   (LLaMA 3.1)   (Markdown)
↓           ↓            ↓
FastAPI REST API
##  Agents

| Agent | Role | Tool |
|-------|------|------|
| Researcher | Fetches CVEs by keyword | NVD API |
| Summarizer | AI threat analysis | Groq LLaMA 3.1 |
| Report Writer | Structured report generation | Python |

##  Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Add your GROQ_API_KEY

# Run the API
uvicorn api.main:app --reload --port 8000
```

##  API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/analyze` | Run full multi-agent analysis |
| GET | `/results/{job_id}` | Get analysis by ID |
| GET | `/history` | List all analyses |
| GET | `/health` | System health check |

##  Tech Stack
- **LangGraph** — Agent orchestration & state management
- **Groq API** — LLaMA 3.1 8B inference (free tier)
- **FastAPI** — REST API
- **NVD API** — CVE vulnerability database
- **Python 3.10+**