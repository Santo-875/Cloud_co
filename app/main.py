"""FastAPI main application exposing Cloud Copilot REST endpoints."""

import os
import time
from collections import defaultdict
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.config import settings
from app.cost.estimator import CostEstimator
from app.graph import ArchitectureGraph
from app.llm.client import GeminiClient, LLMClient, MockLLMClient
from app.llm.explainer import ArchitectureExplainer
from app.models import Architecture, Finding
from app.parser import ParserError, parse_architecture
from app.security.runner import SecurityScannerRunner
from app.store import GLOBAL_STORE
from app.terraform.generator import TerraformGenerator

app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description="Deterministic and Grounded Cloud Architecture Security Copilot",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory rate limiting state: client_ip -> list of timestamps
_chat_rate_limits: dict[str, list[float]] = defaultdict(list)


def get_client_ip(request: Request) -> str:
    """Extract client IP, strictly ignoring X-Forwarded-For unless trusted_proxy_headers is true."""
    if settings.trusted_proxy_headers:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


def enforce_chat_rate_limit(client_ip: str) -> None:
    now = time.time()
    cutoff = now - 60.0
    timestamps = [t for t in _chat_rate_limits[client_ip] if t > cutoff]
    if len(timestamps) >= settings.chat_rate_limit_per_minute:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded on /chat (maximum {settings.chat_rate_limit_per_minute} requests/minute).",
        )
    timestamps.append(now)
    _chat_rate_limits[client_ip] = timestamps


def get_llm_client() -> LLMClient:
    """Provide MockLLMClient if configured or if GEMINI_API_KEY is absent."""
    if settings.use_mock_llm or not os.environ.get("GEMINI_API_KEY"):
        return MockLLMClient()
    try:
        return GeminiClient()
    except (ValueError, RuntimeError):
        return MockLLMClient()


# Request / Response Schemas
class CreateArchitectureResponse(BaseModel):
    id: str
    name: str
    region: str
    nodes_count: int
    edges_count: int


class TerraformResponse(BaseModel):
    files: dict[str, str]


class ScanResponse(BaseModel):
    findings: list[Finding]
    scanners_run: list[str]


class ChatRequest(BaseModel):
    architecture_id: str
    message: str
    mode: Literal["explain_architecture", "explain_findings", "answer_question"] = (
        "answer_question"
    )


class ChatResponse(BaseModel):
    response: str
    sources: list[str]


# Endpoints


@app.get("/health")
def health() -> dict[str, str]:
    """Service health probe."""
    return {"status": "ok", "version": settings.version}


@app.post(
    "/architecture",
    status_code=status.HTTP_201_CREATED,
    response_model=CreateArchitectureResponse,
)
async def create_architecture(request: Request) -> CreateArchitectureResponse:
    """Parse, validate, and store architecture from YAML string, JSON string, or JSON dictionary."""
    content_type = request.headers.get("content-type", "")
    body_bytes = await request.body()

    try:
        if "application/json" in content_type:
            payload = await request.json()
            arch = parse_architecture(payload)
        else:
            raw_text = body_bytes.decode("utf-8")
            arch = parse_architecture(raw_text)
    except ParserError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid payload: {exc}",
        ) from exc

    arch_id = GLOBAL_STORE.save(arch)
    return CreateArchitectureResponse(
        id=arch_id,
        name=arch.name,
        region=arch.region,
        nodes_count=len(arch.nodes),
        edges_count=len(arch.edges),
    )


@app.get("/architecture/{arch_id}", response_model=Architecture)
def get_architecture(arch_id: str) -> Architecture:
    """Retrieve stored architecture by ID."""
    arch = GLOBAL_STORE.get(arch_id)
    if not arch:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Architecture '{arch_id}' not found or expired.",
        )
    return arch


@app.get("/architecture/{arch_id}/graph")
def get_architecture_graph(arch_id: str) -> dict[str, Any]:
    """Retrieve visual graph topology with clusters."""
    arch = GLOBAL_STORE.get(arch_id)
    if not arch:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Architecture '{arch_id}' not found.",
        )
    graph = ArchitectureGraph(arch)
    return graph.to_visualization_dict()


@app.post(
    "/architecture/{arch_id}/terraform",
    response_model=TerraformResponse,
)
def generate_terraform(arch_id: str) -> TerraformResponse:
    """Generate deterministic Terraform configuration files."""
    arch = GLOBAL_STORE.get(arch_id)
    if not arch:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Architecture '{arch_id}' not found.",
        )
    generator = TerraformGenerator(arch)
    files = generator.generate()
    return TerraformResponse(files=files)


@app.post("/architecture/{arch_id}/scan", response_model=ScanResponse)
def scan_architecture(arch_id: str) -> ScanResponse:
    """Execute graph rules and external security scanners."""
    arch = GLOBAL_STORE.get(arch_id)
    if not arch:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Architecture '{arch_id}' not found.",
        )
    runner = SecurityScannerRunner(arch)
    findings, scanners = runner.run_scans()
    return ScanResponse(findings=findings, scanners_run=scanners)


@app.get("/architecture/{arch_id}/cost")
def get_architecture_cost(arch_id: str) -> dict[str, Any]:
    """Calculate estimated monthly infrastructure cost."""
    arch = GLOBAL_STORE.get(arch_id)
    if not arch:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Architecture '{arch_id}' not found.",
        )
    estimator = CostEstimator()
    report = estimator.estimate(arch)
    return {
        "line_items": report.line_items,
        "total_monthly_usd": report.total_monthly_usd,
        "assumptions": report.assumptions,
        "disclaimer": report.disclaimer,
        "last_updated": report.last_updated,
    }


@app.post("/chat", response_model=ChatResponse)
def chat_explainer(req: ChatRequest, request: Request) -> ChatResponse:
    """Grounded security explainer Q&A endpoint with rate limiting."""
    client_ip = get_client_ip(request)
    enforce_chat_rate_limit(client_ip)

    arch = GLOBAL_STORE.get(req.architecture_id)
    if not arch:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Architecture '{req.architecture_id}' not found.",
        )

    # Gather scan findings to ground explanations
    runner = SecurityScannerRunner(arch)
    findings, _ = runner.run_scans()

    llm = get_llm_client()
    explainer = ArchitectureExplainer(llm_client=llm)

    if req.mode == "explain_architecture":
        text, sources = explainer.explain_architecture(arch)
    elif req.mode == "explain_findings":
        text, sources = explainer.explain_findings(arch, findings)
    else:
        text, sources = explainer.answer_question(arch, findings, req.message)

    return ChatResponse(response=text, sources=sources)
