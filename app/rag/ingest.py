"""Document chunking and ingestion for the security knowledge corpus."""

import re
from dataclasses import dataclass
from pathlib import Path

CORPUS_DIR = Path(__file__).parent / "corpus"


@dataclass
class DocumentChunk:
    chunk_id: str
    content: str
    service: str
    check_id: str
    severity: str
    source_file: str


def parse_metadata_header(text: str) -> tuple[dict[str, str], str]:
    """Extract metadata header lines (Service:, CheckID:, Severity:) and return remaining body."""
    metadata: dict[str, str] = {
        "service": "general",
        "check_id": "general",
        "severity": "medium",
    }
    body_lines: list[str] = []
    lines = text.splitlines()
    in_header = True

    for line in lines:
        stripped = line.strip()
        if in_header:
            if stripped.startswith("#"):
                continue
            if ":" in stripped and not stripped.startswith("##"):
                key, val = stripped.split(":", 1)
                k_norm = key.strip().lower()
                if k_norm in ("service", "checkid", "check_id", "severity"):
                    norm_k = "check_id" if k_norm in ("checkid", "check_id") else k_norm
                    metadata[norm_k] = val.strip()
                    continue
            elif stripped:
                in_header = False
                body_lines.append(line)
        else:
            body_lines.append(line)

    return metadata, "\n".join(body_lines).strip()


def chunk_text(text: str, max_words: int = 350) -> list[str]:
    """Split text into 300-500 token/word chunks preserving paragraph boundaries."""
    paragraphs = re.split(r"\n\s*\n", text)
    chunks: list[str] = []
    curr_chunk: list[str] = []
    curr_len = 0

    for para in paragraphs:
        p_text = para.strip()
        if not p_text:
            continue
        p_len = len(p_text.split())
        if curr_len + p_len > max_words and curr_chunk:
            chunks.append("\n\n".join(curr_chunk))
            curr_chunk = [p_text]
            curr_len = p_len
        else:
            curr_chunk.append(p_text)
            curr_len += p_len

    if curr_chunk:
        chunks.append("\n\n".join(curr_chunk))
    return chunks


def load_and_chunk_corpus(corpus_dir: Path | None = None) -> list[DocumentChunk]:
    """Scan corpus directory and generate chunked knowledge objects."""
    target_dir = corpus_dir or CORPUS_DIR
    chunks: list[DocumentChunk] = []

    if not target_dir.exists():
        return chunks

    for file_path in target_dir.glob("*.md"):
        content = file_path.read_text(encoding="utf-8")
        meta, body = parse_metadata_header(content)
        text_chunks = chunk_text(body)

        for idx, text in enumerate(text_chunks):
            chunk_id = f"{file_path.stem}_{idx}"
            chunks.append(
                DocumentChunk(
                    chunk_id=chunk_id,
                    content=text,
                    service=meta["service"],
                    check_id=meta["check_id"],
                    severity=meta["severity"],
                    source_file=file_path.name,
                )
            )

    return chunks
