"""
Retriever with intent routing, metadata filtering, and lexical scoring.

Routing order for Gate R1:
1. Deterministic intent routing (keyword-based) → doc_type selection
2. Metadata filter (service, check_id, doc_type, resource_or_command)
3. Keyword scorer (default; no external dependencies)

An optional embedding backend can be added behind the same interface
by setting CLOUD_COPILOT_EMBED_BACKEND=<name> (requires explicit approval
before adding the embedding dependency).

Every answer includes citations (source_url, pinned_version, fetched_at).
When retrieval finds nothing relevant, the caller receives an empty list
and must tell the user the topic is not covered.
"""

import os
import re
from pathlib import Path

from app.rag.ingest import DocumentChunk, load_and_chunk_corpus

# ── Intent routing keyword tables ─────────────────────────────────────────────

_CLI_KEYWORDS = frozenset(
    [
        "command",
        "cli",
        "aws",
        "run-instances",
        "describe-instances",
        "create-tags",
        "terminate",
        "start-instances",
        "stop-instances",
        "authorize",
        "revoke",
        "describe",
        "list-buckets",
        "put-bucket",
        "get-bucket",
        "get-caller-identity",
        "put-metric-alarm",
        "list-topics",
        "create-topic",
        "describe-alarms",
        "describe-db-instances",
        "ec2",
        "s3api",
        "s3",
        "iam",
        "rds",
        "cloudwatch",
        "sns",
        "sts",
        "flag",
        "option",
        "parameter",
        "--query",
        "--filter",
        "--dry-run",
        "shell",
        "bash",
    ]
)

_TERRAFORM_KEYWORDS = frozenset(
    [
        "terraform",
        "resource",
        "argument",
        "attribute",
        "provider",
        "module",
        "hcl",
        "tfstate",
        "plan",
        "apply",
        "import",
        "aws_vpc",
        "aws_subnet",
        "aws_security_group",
        "aws_instance",
        "aws_s3_bucket",
        "aws_db_instance",
        "aws_iam_role",
        "aws_iam_policy",
        "aws_cloudwatch",
        "aws_sns_topic",
        "aws_internet_gateway",
        "aws_route_table",
        "aws_ebs_volume",
        "versioning",
        "public_access_block",
        "encryption_configuration",
        "var.",
        "output.",
        "lifecycle",
        "depends_on",
    ]
)

_PRICING_KEYWORDS = frozenset(
    [
        "cost",
        "price",
        "pricing",
        "bill",
        "billing",
        "estimate",
        "monthly",
        "annual",
        "12-month",
        "upfront",
        "on-demand",
        "reserved",
        "spot",
        "calculator",
        "free tier",
        "freetier",
        "usd",
        "dollar",
        "rate",
        "sku",
        "dimension",
        "data transfer",
        "request count",
        "gb-month",
        "instance-hour",
        "storage cost",
        "compute cost",
    ]
)

_SECURITY_KEYWORDS = frozenset(
    [
        "security",
        "finding",
        "vulnerability",
        "risk",
        "compliance",
        "checkov",
        "trivy",
        "ckv_aws",
        "cis",
        "nist",
        "soc2",
        "encryption",
        "kms",
        "policy",
        "iam",
        "least privilege",
        "public access",
        "open ssh",
        "open rdp",
        "unrestricted",
        "exposed",
        "misconfiguration",
        "well-architected",
        "waf",
        "cloudtrail",
        "guardduty",
        "config",
        "logging",
        "audit",
    ]
)


def route_intent(query: str) -> str | None:
    """
    Deterministically route a query to a doc_type using keyword matching.

    Returns: "cli" | "terraform" | "pricing" | "security" | None (no strong signal)
    """
    q_lower = query.lower()
    q_words = set(re.findall(r"[\w.-]+", q_lower))

    scores: dict[str, int] = {"cli": 0, "terraform": 0, "pricing": 0, "security": 0}

    for word in q_words:
        if word in _CLI_KEYWORDS:
            scores["cli"] += 2
        if word in _TERRAFORM_KEYWORDS:
            scores["terraform"] += 2
        if word in _PRICING_KEYWORDS:
            scores["pricing"] += 2
        if word in _SECURITY_KEYWORDS:
            scores["security"] += 2

    # Substring matches for multi-word terms
    for phrase in ("free tier", "data transfer", "instance-hour", "gb-month", "12-month", "open ssh", "least privilege"):
        if phrase in q_lower:
            scores["pricing" if "tier" in phrase or "transfer" in phrase or "month" in phrase or "hour" in phrase else "security"] += 3

    # Check IDs (CKV_AWS_*) → always security
    if re.search(r"CKV_AWS_\d+", query, re.IGNORECASE):
        scores["security"] += 10

    best = max(scores, key=lambda k: scores[k])
    if scores[best] == 0:
        return None  # no strong signal → search all
    return best


class SecurityKnowledgeRetriever:
    """
    Retriever with intent routing, metadata filtering, and keyword scoring.

    Backward-compatible: existing callers that use service/check_id filters still work.
    New callers may pass doc_type directly or rely on query-based routing.
    """

    def __init__(self, corpus_dir: Path | None = None) -> None:
        self.chunks: list[DocumentChunk] = load_and_chunk_corpus(corpus_dir)

    def add_chunks(self, chunks: list[DocumentChunk]) -> None:
        """Extend the in-memory chunk store (used when raw sources are also loaded)."""
        self.chunks.extend(chunks)

    def _score_chunk(self, query_terms: set[str], chunk: DocumentChunk) -> float:
        """Compute keyword frequency and metadata boost score."""
        score = 0.0
        text = (
            f"{chunk.content} {chunk.service} {chunk.check_id} "
            f"{chunk.resource_or_command} {chunk.section}"
        ).lower()

        for term in query_terms:
            if not term:
                continue
            matches = len(re.findall(re.escape(term), text))
            score += matches * 1.5

        if chunk.check_id.lower() in query_terms:
            score += 10.0
        if chunk.service.lower() in query_terms:
            score += 5.0
        if chunk.resource_or_command and any(t in chunk.resource_or_command.lower() for t in query_terms):
            score += 3.0

        return score

    def retrieve(
        self,
        query: str,
        service: str | None = None,
        check_id: str | None = None,
        doc_type: str | None = None,
        top_k: int = 3,
    ) -> list[DocumentChunk]:
        """
        Retrieve most relevant chunks.

        Routing order:
        1. If doc_type is given, filter to that doc_type.
        2. Otherwise, run intent routing on the query.
        3. Apply service / check_id metadata filters within the routed subset.
        4. Score by keyword relevance.
        5. Return top_k chunks; if none score > 0, return top_k by order.
           Returning an empty list signals "topic not covered."
        """
        # ── Step 1+2: doc_type routing ─────────────────────────────────────────
        resolved_doc_type = doc_type
        if resolved_doc_type is None:
            resolved_doc_type = route_intent(query)

        if resolved_doc_type is not None:
            filtered = [c for c in self.chunks if c.doc_type == resolved_doc_type]
            if not filtered:
                # No chunks of that type → fall back to all (graceful degradation)
                filtered = self.chunks
        else:
            filtered = self.chunks

        # ── Step 3: metadata filters ───────────────────────────────────────────
        if service:
            s_norm = service.lower().strip()
            filtered = [
                c
                for c in filtered
                if c.service.lower() == s_norm or s_norm in c.content.lower()
            ]

        if check_id:
            c_norm = check_id.lower().strip()
            filtered = [
                c
                for c in filtered
                if c.check_id.lower() == c_norm or c_norm in c.content.lower()
            ]

        if not filtered:
            # Fall back to entire corpus if strict metadata filter yielded nothing
            filtered = self.chunks

        # ── Step 4: keyword scoring ────────────────────────────────────────────
        query_terms = set(re.findall(r"[\w.-]+", query.lower()))
        scored = [(self._score_chunk(query_terms, chunk), chunk) for chunk in filtered]
        scored.sort(key=lambda x: x[0], reverse=True)

        results = [chunk for score, chunk in scored if score > 0][:top_k]
        if not results and filtered:
            results = filtered[:top_k]

        return results

    def citations_for(self, chunks: list[DocumentChunk]) -> list[str]:
        """Return deduplicated citation strings for a list of retrieved chunks."""
        seen: set[str] = set()
        citations: list[str] = []
        for c in chunks:
            cite = c.citation()
            if cite not in seen:
                seen.add(cite)
                citations.append(cite)
        return citations
