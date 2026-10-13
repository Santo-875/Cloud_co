"""Retriever with metadata filtering and lexical/semantic scoring fallback."""

import re
from pathlib import Path

from app.rag.ingest import DocumentChunk, load_and_chunk_corpus


class SecurityKnowledgeRetriever:
    """Retrieves security guidelines filtered by metadata (service, check_id) with keyword fallback."""

    def __init__(self, corpus_dir: Path | None = None) -> None:
        self.chunks: list[DocumentChunk] = load_and_chunk_corpus(corpus_dir)

    def _score_chunk(self, query_terms: set[str], chunk: DocumentChunk) -> float:
        """Compute keyword frequency and metadata boost score."""
        score = 0.0
        text = f"{chunk.content} {chunk.service} {chunk.check_id}".lower()

        for term in query_terms:
            if not term:
                continue
            matches = len(re.findall(re.escape(term), text))
            score += matches * 1.5

        if chunk.check_id.lower() in query_terms:
            score += 10.0
        if chunk.service.lower() in query_terms:
            score += 5.0

        return score

    def retrieve(
        self,
        query: str,
        service: str | None = None,
        check_id: str | None = None,
        top_k: int = 3,
    ) -> list[DocumentChunk]:
        """Retrieve most relevant chunks.

        Metadata filtering is applied first, followed by relevance scoring.
        """
        filtered = self.chunks

        # Metadata filters
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

        query_terms = set(re.findall(r"\w+", query.lower()))
        scored = [(self._score_chunk(query_terms, chunk), chunk) for chunk in filtered]
        # Sort by score descending
        scored.sort(key=lambda x: x[0], reverse=True)

        results = [chunk for score, chunk in scored if score > 0][:top_k]
        if not results and filtered:
            results = filtered[:top_k]

        return results
