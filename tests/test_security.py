"""Tests for security runner, deduplication, normalizer, and invariant safety."""

import json
from pathlib import Path

import pytest

from app.models import Architecture, Finding, Node
from app.security.normalizer import (
    deduplicate_and_merge_findings,
    extract_node_id_from_resource_address,
    normalize_checkov_finding,
    normalize_trivy_finding,
)
from app.security.runner import SecurityScannerRunner, run_command_safely

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_invariant_apply_strictly_prohibited(tmp_path) -> None:
    """Critical safety test: verify run_command_safely raises ValueError if 'apply' appears."""
    with pytest.raises(ValueError, match="CRITICAL INVARIANT VIOLATION"):
        run_command_safely(["terraform", "apply", "-auto-approve"], cwd=tmp_path)

    with pytest.raises(ValueError, match="CRITICAL INVARIANT VIOLATION"):
        run_command_safely(["some_tool", "Apply"], cwd=tmp_path)


def test_extract_node_id() -> None:
    assert (
        extract_node_id_from_resource_address("aws_security_group.sg_open_admin")
        == "sg_open_admin"
    )
    assert extract_node_id_from_resource_address("raw_node_id") == "raw_node_id"


def test_normalize_checkov_fixture() -> None:
    checkov_path = FIXTURES_DIR / "checkov_sample.json"
    assert checkov_path.exists()

    data = json.loads(checkov_path.read_text(encoding="utf-8"))
    failed_checks = data["results"]["failed_checks"]
    assert len(failed_checks) == 2

    findings = [normalize_checkov_finding(c) for c in failed_checks]
    assert findings[0].id == "CKV_AWS_24"
    assert findings[0].resource == "sg_open_admin"
    assert findings[0].severity == "high"
    assert findings[0].source == "checkov"

    assert findings[1].id == "CKV_AWS_8"
    assert findings[1].resource == "ec2_bastion"
    assert findings[1].severity == "medium"


def test_normalize_trivy_fixture() -> None:
    trivy_path = FIXTURES_DIR / "trivy_sample.json"
    assert trivy_path.exists()

    data = json.loads(trivy_path.read_text(encoding="utf-8"))
    misconfigs = data["Results"][0]["Misconfigurations"]
    assert len(misconfigs) == 1

    finding = normalize_trivy_finding(misconfigs[0])
    assert finding.id == "AVD-AWS-0107"
    assert finding.resource == "sg_open_admin"
    assert finding.severity == "high"
    assert finding.source == "trivy"


def test_deduplicate_and_merge_findings() -> None:
    f_graph = Finding(
        id="RULE_OPEN_SSH",
        ids=["RULE_OPEN_SSH"],
        severity="high",
        resource="sg_open_admin",
        title="Port 22 SSH open to world",
        source="graph_rule",
        sources=["graph_rule"],
        fix_hint="Restrict port 22",
    )
    f_checkov = Finding(
        id="CKV_AWS_24",
        ids=["CKV_AWS_24"],
        severity="medium",
        resource="sg_open_admin",
        title="Checkov CKV_AWS_24: Ensure no security groups allow 0.0.0.0/0 to port 22",
        source="checkov",
        sources=["checkov"],
        fix_hint="Restrict SSH to trusted CIDR blocks in your security group.",
    )
    f_trivy = Finding(
        id="AVD-AWS-0107",
        ids=["AVD-AWS-0107"],
        severity="high",
        resource="sg_open_admin",
        title="Trivy AVD-AWS-0107: Admin SSH exposure",
        source="trivy",
        sources=["trivy"],
        fix_hint="Remove 0.0.0.0/0 from ingress rules.",
    )

    merged = deduplicate_and_merge_findings([f_graph, f_checkov, f_trivy])
    assert len(merged) == 1

    result = merged[0]
    assert result.resource == "sg_open_admin"
    assert result.severity == "high"  # Escalated to highest severity
    # Preserves all sources
    assert set(result.sources) == {"graph_rule", "checkov", "trivy"}
    # Preserves all check IDs
    assert set(result.ids) == {"RULE_OPEN_SSH", "CKV_AWS_24", "AVD-AWS-0107"}


def test_security_scanner_runner_offline() -> None:
    """Verify scanner runner executes graph rules and handles missing CLI tools without errors."""
    arch = Architecture(
        name="scanner_test",
        region="us-east-1",
        nodes=[
            Node(id="vpc_1", type="vpc", props={"cidr": "10.0.0.0/16"}),
            Node(
                id="sub_1",
                type="subnet",
                parent="vpc_1",
                props={"cidr": "10.0.1.0/24", "public": False},
            ),
            Node(
                id="sg_1",
                type="security_group",
                parent="vpc_1",
                props={
                    "ingress": [
                        {
                            "port": 22,
                            "cidr": "0.0.0.0/0",
                            "protocol": "tcp",
                        }
                    ]
                },
            ),
        ],
    )
    runner = SecurityScannerRunner(arch)
    findings, scanners_run = runner.run_scans()

    assert "graph_rule" in scanners_run
    # Should at least contain the open SSH finding from graph rules
    ssh_findings = [f for f in findings if "SSH" in f.id or "SSH" in f.title]
    assert len(ssh_findings) >= 1
