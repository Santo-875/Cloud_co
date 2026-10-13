"""Tests for RAG ingestion, metadata-based retriever, and prompt formatting."""

from app.rag.ingest import chunk_text, parse_metadata_header
from app.rag.retriever import SecurityKnowledgeRetriever


def test_parse_metadata_header() -> None:
    doc = """
# TITLE COMMENT
Service: security_group
CheckID: CKV_AWS_24
Severity: high

## Security Risk
Port 22 is open.
"""
    meta, body = parse_metadata_header(doc)
    assert meta["service"] == "security_group"
    assert meta["check_id"] == "CKV_AWS_24"
    assert meta["severity"] == "high"
    assert "Port 22 is open." in body


def test_chunk_text_length() -> None:
    text = "\n\n".join([f"Paragraph {i} with several sample words." for i in range(20)])
    chunks = chunk_text(text, max_words=25)
    assert len(chunks) > 1
    for c in chunks:
        assert len(c.split()) <= 40


def test_retriever_metadata_filtering() -> None:
    retriever = SecurityKnowledgeRetriever()
    assert len(retriever.chunks) >= 3

    # Filter for SSH check
    results = retriever.retrieve("ssh security exposure", check_id="CKV_AWS_24")
    assert len(results) > 0
    assert any("22" in r.content or "SSH" in r.content for r in results)

    # Filter for S3
    s3_results = retriever.retrieve("bucket public", service="s3")
    assert len(s3_results) > 0
    assert any("s3" in r.source_file.lower() for r in s3_results)
