"""Extended DocumentChunk with full source-aware metadata for Gate R1."""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CORPUS_DIR = Path(__file__).parent / "corpus"

# Recognized doc_type values (kept as a frozen set for validation)
DOC_TYPES = frozenset(["cli", "terraform", "pricing", "security"])


@dataclass
class DocumentChunk:
    """A single retrievable chunk of reference documentation."""

    # ── Identifiers ────────────────────────────────────────────────────────────
    chunk_id: str
    content: str

    # ── Legacy fields (kept for backward compat with existing corpus & tests) ──
    service: str = "general"
    check_id: str = "general"
    severity: str = "medium"
    source_file: str = ""

    # ── New R1 metadata ────────────────────────────────────────────────────────
    doc_type: str = "security"  # cli | terraform | pricing | security
    resource_or_command: str = ""
    source_url: str = ""
    pinned_version: str = ""
    fetched_at: str = ""
    license: str = ""
    warnings: list[str] = field(default_factory=list)
    section: str = ""

    def citation(self) -> str:
        """Human-readable citation string for this chunk."""
        parts = [self.source_url or self.source_file]
        if self.pinned_version:
            parts.append(f"@{self.pinned_version}")
        if self.fetched_at:
            parts.append(f"(fetched {self.fetched_at})")
        if self.license:
            parts.append(f"[{self.license}]")
        return " ".join(parts)


# ── Legacy metadata-header parser (unchanged for backward compat) ──────────────


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


# ── Per-type parsers ──────────────────────────────────────────────────────────


def _extract_warnings(text: str) -> list[str]:
    """Extract lines or sentences that contain warning/important/caution keywords."""
    warning_patterns = [
        r"(?i)(warning|important|caution|note)[:\s].*",
        r"(?i)(terminating|terminate)[^.]*permanent[^.]*\.",
        r"(?i)(billed|billing|charges)[^.]*idle[^.]*\.",
        r"(?i)(do not|don't|never|avoid)[^.]*\.",
    ]
    found: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        for pat in warning_patterns:
            if re.search(pat, line):
                found.append(line)
                break
    return found[:10]  # cap at 10 per chunk


def parse_cli_guide(
    text: str,
    source_id: str,
    source_url: str,
    pinned_version: str,
    fetched_at: str,
    license_note: str,
    service: str = "general",
) -> list[DocumentChunk]:
    """
    Parse an AWS CLI user guide page.

    Chunks by section heading. Extracts:
    - section name
    - command names mentioned (used as resource_or_command)
    - warning/important notes (stored as metadata.warnings)
    """
    chunks: list[DocumentChunk] = []
    # Split by markdown-style headings (# ## ###) or HTML-style sections
    sections = re.split(r"\n(?=#{1,3}\s)", text)
    if len(sections) <= 1:
        # No heading-based sections; fall back to paragraph chunks
        sections = [text]

    for sec_idx, section_text in enumerate(sections):
        if not section_text.strip():
            continue

        # Extract heading name
        heading_match = re.match(r"^#{1,3}\s+(.+)", section_text.strip())
        section_name = heading_match.group(1).strip() if heading_match else f"section_{sec_idx}"

        # Find AWS CLI command names mentioned (aws <service> <command>)
        cmd_matches = re.findall(r"aws\s+([a-z0-9-]+)\s+([a-z0-9-]+)", section_text)
        commands = list({f"{svc} {cmd}" for svc, cmd in cmd_matches})
        resource_or_command = ", ".join(commands[:5]) if commands else ""

        warnings = _extract_warnings(section_text)

        text_chunks = chunk_text(section_text)
        for idx, chunk_content in enumerate(text_chunks):
            chunks.append(
                DocumentChunk(
                    chunk_id=f"{source_id}_s{sec_idx}_c{idx}",
                    content=chunk_content,
                    service=service,
                    check_id="general",
                    severity="medium",
                    source_file=f"{source_id}.html",
                    doc_type="cli",
                    resource_or_command=resource_or_command,
                    source_url=source_url,
                    pinned_version=pinned_version,
                    fetched_at=fetched_at,
                    license=license_note,
                    warnings=warnings,
                    section=section_name,
                )
            )
    return chunks


def parse_cli_reference(
    text: str,
    source_id: str,
    source_url: str,
    pinned_version: str,
    fetched_at: str,
    license_note: str,
    service: str = "general",
) -> list[DocumentChunk]:
    """
    Parse an AWS CLI v2 command reference index page.

    Chunks by command entry. Extracts command name, options, examples.
    """
    chunks: list[DocumentChunk] = []
    # Split by top-level command entries (bold or heading pattern)
    sections = re.split(r"\n(?=#{1,3}\s)", text)
    if len(sections) <= 1:
        sections = [text]

    for sec_idx, section_text in enumerate(sections):
        if not section_text.strip():
            continue

        heading_match = re.match(r"^#{1,3}\s+(.+)", section_text.strip())
        section_name = heading_match.group(1).strip() if heading_match else f"command_{sec_idx}"

        # Extract option flags
        options = re.findall(r"--[a-z][a-z0-9-]+", section_text)
        resource_or_command = section_name if section_name.startswith("aws") else f"aws {service} {section_name}"

        warnings = _extract_warnings(section_text)
        text_chunks = chunk_text(section_text)

        for idx, chunk_content in enumerate(text_chunks):
            chunks.append(
                DocumentChunk(
                    chunk_id=f"{source_id}_s{sec_idx}_c{idx}",
                    content=chunk_content,
                    service=service,
                    check_id="general",
                    severity="medium",
                    source_file=f"{source_id}.html",
                    doc_type="cli",
                    resource_or_command=resource_or_command,
                    source_url=source_url,
                    pinned_version=pinned_version,
                    fetched_at=fetched_at,
                    license=license_note,
                    warnings=warnings,
                    section=section_name,
                )
            )
    return chunks


def parse_terraform_provider(
    text: str,
    source_id: str,
    source_url: str,
    pinned_version: str,
    fetched_at: str,
    license_note: str,
    resource_name: str = "",
) -> list[DocumentChunk]:
    """
    Parse a Terraform AWS provider .html.markdown resource doc.

    Chunks by section:
    - front matter (resource name, description)
    - Example Usage
    - Argument Reference
    - Attribute Reference
    - Import

    Each chunk carries: service=aws, resource_or_command=<resource_type>
    """
    chunks: list[DocumentChunk] = []

    # Parse front matter
    fm_match = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
    front_matter_meta: dict[str, str] = {}
    body = text
    if fm_match:
        fm_text = fm_match.group(1)
        body = text[fm_match.end():]
        for line in fm_text.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                front_matter_meta[k.strip().lower()] = v.strip().strip('"\'')

    page_description = front_matter_meta.get("description", "")
    resource_type = front_matter_meta.get("subcategory", resource_name) or resource_name

    # Split by section headings
    sections = re.split(r"\n(?=#{1,3}\s)", body)

    for sec_idx, section_text in enumerate(sections):
        if not section_text.strip():
            continue
        heading_match = re.match(r"^#{1,3}\s+(.+)", section_text.strip())
        section_name = heading_match.group(1).strip() if heading_match else f"section_{sec_idx}"

        warnings = _extract_warnings(section_text)
        text_chunks = chunk_text(section_text)

        for idx, chunk_content in enumerate(text_chunks):
            chunks.append(
                DocumentChunk(
                    chunk_id=f"{source_id}_s{sec_idx}_c{idx}",
                    content=chunk_content,
                    service="aws",
                    check_id="general",
                    severity="medium",
                    source_file=f"{source_id}.md",
                    doc_type="terraform",
                    resource_or_command=resource_type or resource_name,
                    source_url=source_url,
                    pinned_version=pinned_version,
                    fetched_at=fetched_at,
                    license=license_note,
                    warnings=warnings,
                    section=section_name,
                )
            )
    return chunks


def parse_pricing_concept(
    text: str,
    source_id: str,
    source_url: str,
    pinned_version: str,
    fetched_at: str,
    license_note: str,
) -> list[DocumentChunk]:
    """
    Parse AWS Pricing Calculator user guide or Well-Architected cost pillar.

    Chunks by heading.
    """
    chunks: list[DocumentChunk] = []
    sections = re.split(r"\n(?=#{1,3}\s)", text)
    if len(sections) <= 1:
        sections = [text]

    for sec_idx, section_text in enumerate(sections):
        if not section_text.strip():
            continue
        heading_match = re.match(r"^#{1,3}\s+(.+)", section_text.strip())
        section_name = heading_match.group(1).strip() if heading_match else f"section_{sec_idx}"

        text_chunks = chunk_text(section_text)
        for idx, chunk_content in enumerate(text_chunks):
            chunks.append(
                DocumentChunk(
                    chunk_id=f"{source_id}_s{sec_idx}_c{idx}",
                    content=chunk_content,
                    service="aws",
                    check_id="general",
                    severity="medium",
                    source_file=f"{source_id}.html",
                    doc_type="pricing",
                    resource_or_command="",
                    source_url=source_url,
                    pinned_version=pinned_version,
                    fetched_at=fetched_at,
                    license=license_note,
                    warnings=[],
                    section=section_name,
                )
            )
    return chunks


def parse_security_check(
    text: str,
    source_id: str,
    source_url: str,
    pinned_version: str,
    fetched_at: str,
    license_note: str,
) -> list[DocumentChunk]:
    """
    Parse Checkov policy docs or Well-Architected security pillar.

    Extracts check IDs (CKV_AWS_*) and chunks by heading.
    """
    chunks: list[DocumentChunk] = []
    sections = re.split(r"\n(?=#{1,3}\s)", text)
    if len(sections) <= 1:
        sections = [text]

    for sec_idx, section_text in enumerate(sections):
        if not section_text.strip():
            continue
        heading_match = re.match(r"^#{1,3}\s+(.+)", section_text.strip())
        section_name = heading_match.group(1).strip() if heading_match else f"section_{sec_idx}"

        # Extract check ids
        check_ids = re.findall(r"CKV_AWS_\d+", section_text)
        check_id_str = check_ids[0] if check_ids else "general"

        text_chunks = chunk_text(section_text)
        for idx, chunk_content in enumerate(text_chunks):
            chunks.append(
                DocumentChunk(
                    chunk_id=f"{source_id}_s{sec_idx}_c{idx}",
                    content=chunk_content,
                    service="aws",
                    check_id=check_id_str,
                    severity="medium",
                    source_file=f"{source_id}.html",
                    doc_type="security",
                    resource_or_command="",
                    source_url=source_url,
                    pinned_version=pinned_version,
                    fetched_at=fetched_at,
                    license=license_note,
                    warnings=[],
                    section=section_name,
                )
            )
    return chunks


# ── Dispatcher ────────────────────────────────────────────────────────────────

PARSER_MAP = {
    "cli_guide": parse_cli_guide,
    "cli_reference": parse_cli_reference,
    "terraform_provider": parse_terraform_provider,
    "pricing_concept": parse_pricing_concept,
    "security_check": parse_security_check,
}


def parse_raw_document(
    text: str,
    source_meta: dict[str, Any],
) -> list[DocumentChunk]:
    """
    Route a raw fetched document to the appropriate parser based on source metadata.

    source_meta fields: id, type, url_or_repo, pinned_version, license_note, parser
    """
    src_type = source_meta.get("parser", source_meta.get("type", "security_check"))
    src_id = source_meta.get("id", "unknown")
    source_url = source_meta.get("url_or_repo", "")
    pinned = source_meta.get("pinned_version", "")
    fetched_at = source_meta.get("fetched_at", "")
    license_note = source_meta.get("license_note", "")

    fn = PARSER_MAP.get(src_type)
    if fn is None:
        # Unknown type: fall back to security_check chunker
        fn = parse_security_check

    # Determine service from id heuristic
    service = "general"
    if "ec2" in src_id:
        service = "ec2"
    elif "s3" in src_id:
        service = "s3"
    elif "iam" in src_id:
        service = "iam"
    elif "rds" in src_id:
        service = "rds"
    elif "cloudwatch" in src_id:
        service = "cloudwatch"
    elif "sns" in src_id:
        service = "sns"
    elif "sts" in src_id:
        service = "sts"
    elif "vpc" in src_id or "subnet" in src_id or "sg" in src_id or "security_group" in src_id:
        service = "ec2"

    # Determine resource name for terraform
    resource_name = ""
    if src_type == "terraform_provider":
        resource_name = src_id.replace("tf_aws_", "aws_")

    if src_type in ("cli_guide", "cli_reference"):
        return fn(
            text=text,
            source_id=src_id,
            source_url=source_url,
            pinned_version=pinned,
            fetched_at=fetched_at,
            license_note=license_note,
            service=service,
        )
    elif src_type == "terraform_provider":
        return fn(
            text=text,
            source_id=src_id,
            source_url=source_url,
            pinned_version=pinned,
            fetched_at=fetched_at,
            license_note=license_note,
            resource_name=resource_name,
        )
    else:
        return fn(
            text=text,
            source_id=src_id,
            source_url=source_url,
            pinned_version=pinned,
            fetched_at=fetched_at,
            license_note=license_note,
        )


# ── Legacy corpus loader (unchanged interface) ─────────────────────────────────


def load_and_chunk_corpus(corpus_dir: Path | None = None) -> list[DocumentChunk]:
    """Scan corpus directory and generate chunked knowledge objects.

    Backward-compatible: loads .md files from the corpus/ directory using the
    legacy metadata-header format. New sources ingested from data/raw/ use
    load_raw_sources() instead.
    """
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
                    doc_type="security",
                )
            )

    return chunks


def load_raw_sources(
    raw_dir: Path,
    manifest: list[dict[str, Any]],
) -> list[DocumentChunk]:
    """
    Load and parse fetched raw documents from data/raw/ using the manifest for metadata.

    Files in raw_dir are matched by source id to manifest entries.
    """
    chunks: list[DocumentChunk] = []
    manifest_by_id = {src["id"]: src for src in manifest}

    for raw_file in raw_dir.glob("*"):
        if raw_file.name.startswith("."):
            continue
        # Match file stem to manifest id
        src_id = raw_file.stem
        source_meta = manifest_by_id.get(src_id)
        if source_meta is None:
            continue
        if source_meta.get("type") == "price_data":
            continue  # price data handled separately

        try:
            text = raw_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        doc_chunks = parse_raw_document(text, source_meta)
        chunks.extend(doc_chunks)

    return chunks
