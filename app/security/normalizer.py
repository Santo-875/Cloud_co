"""Fix hints and normalizer for security findings from graph rules and scanners."""

from typing import Any, Literal

from app.models import Finding

SEVERITY_ORDER: dict[str, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

FIX_HINTS: dict[str, str] = {
    "CKV_AWS_24": "Restrict port 22 SSH ingress to a trusted bastion host or internal IP range.",
    "CKV_AWS_20": "Set 'public: false' and configure S3 Block Public Access.",
    "CKV_AWS_17": "Set 'publicly_accessible: false' to ensure RDS is confined to internal subnets.",
    "CKV_AWS_3": "Enable KMS or AES-256 storage encryption on the EBS volume.",
    "CKV_AWS_8": "Enable encrypted storage for EC2 root block devices.",
    "CKV_AWS_16": "Set 'storage_encrypted: true' on RDS database instance.",
    "CKV_AWS_21": "Enable versioning on the S3 bucket to protect against accidental overwrites.",
    "AVD-AWS-0107": "Restrict security group ingress rule CIDR to non-public addresses.",
}


def extract_node_id_from_resource_address(address: str) -> str:
    """Extract node id from terraform resource address like 'aws_security_group.sg_open_admin'."""
    if "." in address:
        return address.split(".", 1)[1]
    return address


def normalize_checkov_finding(item: dict[str, Any]) -> Finding:
    """Map raw checkov check result into normalized Finding."""
    check_id = str(item.get("check_id", "CKV_UNKNOWN"))
    raw_sev = str(item.get("severity", "MEDIUM")).lower()
    severity: Literal["low", "medium", "high", "critical"] = (
        raw_sev if raw_sev in SEVERITY_ORDER else "medium"
    )  # type: ignore[assignment]
    raw_res = str(item.get("resource", ""))
    resource_id = extract_node_id_from_resource_address(raw_res)
    title = str(item.get("check_name", f"Checkov violation: {check_id}"))
    hint = FIX_HINTS.get(check_id, item.get("guideline"))

    return Finding(
        id=check_id,
        ids=[check_id],
        severity=severity,
        resource=resource_id,
        title=title,
        source="checkov",
        sources=["checkov"],
        fix_hint=hint,
    )


def normalize_trivy_finding(item: dict[str, Any]) -> Finding:
    """Map raw trivy misconfiguration result into normalized Finding."""
    check_id = str(item.get("ID", item.get("AVDID", "TRIVY_UNKNOWN")))
    raw_sev = str(item.get("Severity", "MEDIUM")).lower()
    severity: Literal["low", "medium", "high", "critical"] = (
        raw_sev if raw_sev in SEVERITY_ORDER else "medium"
    )  # type: ignore[assignment]

    cause = item.get("CauseMetadata", {})
    raw_res = str(cause.get("Resource", item.get("Target", "")))
    resource_id = extract_node_id_from_resource_address(raw_res)
    title = str(
        item.get("Title", item.get("Message", f"Trivy misconfiguration: {check_id}"))
    )
    hint = FIX_HINTS.get(check_id, item.get("Resolution"))

    return Finding(
        id=check_id,
        ids=[check_id],
        severity=severity,
        resource=resource_id,
        title=title,
        source="trivy",
        sources=["trivy"],
        fix_hint=hint,
    )


def _categorize_finding(finding: Finding) -> str:
    """Determine thematic security category for deduplication (resource, category)."""
    check_str = f"{finding.id} {finding.title} {' '.join(finding.ids)}".lower()
    if "ssh" in check_str or "22" in check_str or "admin" in check_str:
        return "ssh_open"
    if "rdp" in check_str or "3389" in check_str:
        return "rdp_open"
    if "public_s3" in check_str or "s3" in check_str and "public" in check_str:
        return "s3_public"
    if "public_rds" in check_str or "rds" in check_str and "public" in check_str:
        return "rds_public"
    if "ebs" in check_str and "encrypt" in check_str:
        return "ebs_encryption"
    if "rds" in check_str and "encrypt" in check_str:
        return "rds_encryption"
    if "versioning" in check_str:
        return "s3_versioning"
    if "subnet" in check_str and "igw" in check_str:
        return "public_subnet_routing"
    return finding.id


def deduplicate_and_merge_findings(findings: list[Finding]) -> list[Finding]:
    """Merge findings matching (resource, category).

    Rules per Contract Section 3.3:
    - Retain highest severity.
    - Retain most specific / descriptive title and fix hint.
    - Preserve complete list of detection sources in `sources`.
    - Preserve complete list of check ids in `ids`.
    - Maintain primary `id` and primary `source`.
    """
    groups: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        cat = _categorize_finding(f)
        key = (f.resource, cat)
        groups.setdefault(key, []).append(f)

    merged_findings: list[Finding] = []
    for (resource, _cat), group in groups.items():
        if len(group) == 1:
            merged_findings.append(group[0])
            continue

        # Find highest severity
        max_sev = max(group, key=lambda x: SEVERITY_ORDER.get(x.severity, 0)).severity

        # Collect unique sources and check IDs
        all_sources: list[Literal["checkov", "trivy", "validate", "graph_rule"]] = []
        for f in group:
            for s in f.sources or [f.source]:
                if s not in all_sources:
                    all_sources.append(s)

        all_ids: list[str] = []
        for f in group:
            for i in f.ids or [f.id]:
                if i not in all_ids:
                    all_ids.append(i)

        # Primary source priority: graph_rule > checkov > trivy > validate
        source_priority = {"graph_rule": 4, "checkov": 3, "trivy": 2, "validate": 1}
        primary_finding = max(group, key=lambda x: source_priority.get(x.source, 0))

        # Best title and hint: pick longest / most informative
        best_title = max(group, key=lambda x: len(x.title)).title
        hints = [x.fix_hint for x in group if x.fix_hint]
        best_hint = max(hints, key=len) if hints else None

        merged = Finding(
            id=primary_finding.id,
            ids=all_ids,
            severity=max_sev,
            resource=resource,
            title=best_title,
            source=primary_finding.source,
            sources=all_sources,
            fix_hint=best_hint,
        )
        merged_findings.append(merged)

    # Sort deterministically by resource then finding id
    merged_findings.sort(key=lambda x: (x.resource, x.id))
    return merged_findings
