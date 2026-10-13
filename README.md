# Cloud Copilot

[![CI/CD Pipeline](https://github.com/Santo-875/Cloud_co/actions/workflows/ci.yml/badge.svg)](https://github.com/Santo-875/Cloud_co/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Security: Gitleaks](https://img.shields.io/badge/security-gitleaks-blueviolet)](https://github.com/gitleaks/gitleaks)

**Cloud Copilot** is a cloud security, DevSecOps, and architecture copilot that parses untrusted cloud architecture specifications, identifies security vulnerabilities using deterministic graph rules and static scanners (Checkov & Trivy), deterministically synthesizes production-ready Terraform HCL, calculates estimated monthly infrastructure bills, and provides grounded explanations through an LLM and RAG pipeline.

---

## 🌟 Core Features

- **Strict Input Validation & Defense**: Safe YAML loading, 100 KB payload ceiling, 200 node limit, cycle detection, and typed schema properties (`extra="forbid"`).
- **Deterministic Graph Rules**: Identifies open SSH/RDP ports, unencrypted storage (EBS/RDS/root), public buckets, and unrouted public subnets before any infrastructure is written.
- **HCL Injection Prevention**: Every user-supplied attribute passes through a universal `hcl_string()` escape filter, eliminating hostile block breakout attempts.
- **The Zero-Apply Invariant**: The system generates and scans code but **strictly prohibits `terraform apply`** or real AWS state changes.
- **Cost Estimation**: Itemized monthly infrastructure pricing calculations with assumptions and disclaimers.
- **Grounded Explainer (RAG + LLM)**: Delimited XML prompt boundaries separate trusted instructions from untrusted data, preventing prompt injection overrides.
- **FastAPI Backend & Streamlit Dashboard**: Single-pane dashboard featuring topology views, severity badges, Terraform viewer, and chat.

---

## 🚀 Quickstart

### 1. Local Setup

```bash
# Clone the repository
git clone https://github.com/Santo-875/Cloud_co.git
cd Cloud_co

# Set up virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .\.venv\Scripts\activate

# Install pinned dependencies
pip install -r requirements.txt
```

### 2. Run Tests & Evaluation

```bash
# Run linters and tests with coverage
ruff check .
black --check .
pytest -v --cov=app

# Run detection evaluation harness against ground truth fixtures
python scripts/eval.py
```

### 3. Run FastAPI Backend

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
API Documentation is available at `http://127.0.0.1:8000/docs`.

### 4. Run Streamlit UI Dashboard

```bash
streamlit run ui/streamlit_app.py
```
Visit `http://localhost:8501` to upload architecture files and explore features.

---

## 🐳 Docker & Docker Compose

Run the complete stack with non-root containers:

```bash
# Build and run API (port 8000) and UI (port 8501)
docker compose up --build
```

---

## 🔒 Security & Threat Model

For details on untrusted boundaries, prompt injection mitigations, and execution invariants, see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

---

## 🛠️ CI/CD Pipeline

The GitHub Actions workflow (`.github/workflows/ci.yml`) enforces:
1. `lint-test`: Ruff, Black, and Pytest with coverage reporting.
2. `security`: Gitleaks secret detection, pip-audit dependencies, Trivy filesystem scan, and Checkov.
3. `terraform-validate`: Generates HCL for test topologies and runs `terraform init -backend=false` and `terraform validate`.
4. `docker-build`: Multi-stage build verification and Trivy vulnerability scan.
5. `deploy`: Production environment approval gate with AWS OIDC role assumption (`CHANGE_ME_COPILOT_DEPLOY_ROLE`). *Note: The deploy job is an approval-gated simulation placeholder and does not execute real infrastructure changes.*
