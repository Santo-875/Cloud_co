"""Explainer module coordinating RAG context retrieval, prompt formatting, and LLM completions."""

from app.llm.client import LLMClient
from app.llm.prompts import (
    TRUSTED_SYSTEM_INSTRUCTION,
    build_explain_architecture_prompt,
    build_explain_findings_prompt,
    build_qa_prompt,
)
from app.models import Architecture, Finding
from app.rag.retriever import SecurityKnowledgeRetriever


class ArchitectureExplainer:
    """Provides grounded architecture explanations and security Q&A using RAG + LLM."""

    def __init__(
        self,
        llm_client: LLMClient,
        retriever: SecurityKnowledgeRetriever | None = None,
    ) -> None:
        self.llm = llm_client
        self.retriever = retriever or SecurityKnowledgeRetriever()

    def explain_architecture(self, architecture: Architecture) -> tuple[str, list[str]]:
        """Generate high-level architecture overview."""
        prompt = build_explain_architecture_prompt(architecture)
        response = self.llm.complete(prompt, system_prompt=TRUSTED_SYSTEM_INSTRUCTION)
        return response, [f"architecture:{architecture.name}"]

    def explain_findings(
        self, architecture: Architecture, findings: list[Finding]
    ) -> tuple[str, list[str]]:
        """Generate risk breakdown and mitigation guidance for security findings."""
        # Retrieve relevant corpus docs for each finding
        rag_chunks = []
        sources = [f"architecture:{architecture.name}"]

        for f in findings:
            sources.append(f"finding:{f.id}")
            # Search by check_id
            chunks = self.retriever.retrieve(
                query=f.title,
                check_id=f.id,
                top_k=2,
            )
            for c in chunks:
                if c not in rag_chunks:
                    rag_chunks.append(c)
                    sources.append(f"doc:{c.source_file}")

        prompt = build_explain_findings_prompt(architecture, findings, rag_chunks)
        response = self.llm.complete(prompt, system_prompt=TRUSTED_SYSTEM_INSTRUCTION)
        return response, sorted(set(sources))

    def answer_question(
        self, architecture: Architecture, findings: list[Finding], question: str
    ) -> tuple[str, list[str]]:
        """Answer specific user question grounded in architecture, findings, and knowledge base."""
        rag_chunks = self.retriever.retrieve(query=question, top_k=3)
        sources = [f"architecture:{architecture.name}"]
        for c in rag_chunks:
            sources.append(f"doc:{c.source_file}")

        prompt = build_qa_prompt(architecture, findings, rag_chunks, question)
        response = self.llm.complete(prompt, system_prompt=TRUSTED_SYSTEM_INSTRUCTION)
        return response, sorted(set(sources))

    def explain_fix(
        self,
        architecture: Architecture,
        diff: str,
        fixed_findings: list[str],
    ) -> str:
        """Generate grounded explanation of applied deterministic remediation."""
        from app.llm.prompts import build_explain_fix_prompt

        prompt = build_explain_fix_prompt(architecture, diff, fixed_findings)
        return self.llm.complete(prompt, system_prompt=TRUSTED_SYSTEM_INSTRUCTION)

    def explain_diagnosis(
        self,
        architecture: Architecture,
        source: str,
        target: str,
        blockers: list,
        graph_evidence: dict,
        question: str,
    ) -> str:
        """Generate grounded explanation of network reachability blockers."""
        from app.llm.prompts import build_explain_diagnose_prompt

        prompt = build_explain_diagnose_prompt(
            architecture, source, target, blockers, graph_evidence, question
        )
        return self.llm.complete(prompt, system_prompt=TRUSTED_SYSTEM_INSTRUCTION)
