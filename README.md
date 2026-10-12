# Cloud Copilot

Cloud Copilot is a design-time AWS architecture assistant that ingests YAML/JSON architecture descriptions, constructs a single source-of-truth **Architecture Graph**, and runs deterministic checks, infrastructure generation, and multi-scanner security audits.

> **Safety Invariant**: Cloud Copilot generates and scans architecture models. It **never** runs `terraform apply` or connects directly to live AWS infrastructure.

---

## Features
- **Deterministic Architecture Graph**: Built with NetworkX from declarative YAML/JSON schemas.
- **Graph Security Rules**: Instant graph topology checks (open ports, unencrypted storage, public S3/RDS, orphaned subnets).
- **Template-driven Terraform Generator**: Jinja2 templates for reproducible, sorted, valid HCL without hallucinated syntax.
- **Unified Security Scanner Normalizer**: Integrates graph rules, `terraform validate`, Checkov, and Trivy into a standardized `Finding` model with deduplication.
- **Transparent Cost Estimator**: Static regional pricing table with explicit assumptions.
- **Grounded LLM Explainer & RAG**: Context-fenced prompts with ChromaDB / keyword retrieval fallback and mock execution for offline testing.
- **Interactive Interfaces**: FastAPI backend and Streamlit dashboard.

---

## Quickstart

### 1. Environment Setup
```bash
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
```

### 2. Run Tests
```bash
pytest -q
```

### 3. Lint and Format
```bash
ruff check .
black --check .
```
