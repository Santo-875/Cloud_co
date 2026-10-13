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


@pytest.mark.parametrize(
    "rule_id,checkov_id,resource_id,rule_title,checkov_title,rule_hint,checkov_hint",
    [
        (
            "RULE_OPEN_SSH",
            "CKV_AWS_24",
            "sg_open_admin",
            "Port 22 SSH open to world",
            "Ensure no security groups allow 0.0.0.0/0 to port 22",
            "Restrict port 22",
            "Restrict SSH to trusted CIDRs",
        ),
        (
            "RULE_UNENCRYPTED_EC2_ROOT",
            "CKV_AWS_8",
            "ec2_bastion",
            "EC2 instance 'ec2_bastion' has unencrypted root/attached storage",
            "Ensure all data stored in the Launch configuration EBS is encrypted",
            "Set 'ebs_encrypted: true'",
            "Enable encryption on root_block_device",
        ),
        (
            "RULE_PUBLIC_RDS",
            "CKV_AWS_17",
            "rds_db",
            "RDS instance 'rds_db' is publicly accessible from the internet",
            "Ensure all data stored in the RDS is not publicly accessible",
            "Set 'publicly_accessible: false'",
            "Disable public accessibility",
        ),
        (
            "RULE_UNENCRYPTED_RDS",
            "CKV_AWS_16",
            "rds_db",
            "RDS instance 'rds_db' does not have KMS storage encryption enabled",
            "Ensure all data stored in the RDS is encrypted",
            "Set 'storage_encrypted: true'",
            "Enable storage encryption",
        ),
        (
            "RULE_PUBLIC_S3",
            "CKV_AWS_20",
            "s3_data",
            "S3 bucket 's3_data' is configured with public access enabled",
            "Ensure S3 bucket is not publicly accessible",
            "Set 'public: false'",
            "Enable Block Public Access",
        ),
    ],
)
def test_dedup_regression_rule_to_check_pairs(
    rule_id: str,
    checkov_id: str,
    resource_id: str,
    rule_title: str,
    checkov_title: str,
    rule_hint: str,
    checkov_hint: str,
) -> None:
    f_rule = Finding(
        id=rule_id,
        ids=[rule_id, checkov_id],
        severity="high",
        resource=resource_id,
        title=rule_title,
        source="graph_rule",
        sources=["graph_rule"],
        fix_hint=rule_hint,
    )
    f_checkov = Finding(
        id=checkov_id,
        ids=[checkov_id],
        severity="medium",
        resource=resource_id,
        title=checkov_title,
        source="checkov",
        sources=["checkov"],
        fix_hint=checkov_hint,
    )
    merged = deduplicate_and_merge_findings([f_rule, f_checkov])
    assert (
        len(merged) == 1
    ), f"Expected 1 merged finding for pair {rule_id}/{checkov_id}, got {len(merged)}"
    assert merged[0].resource == resource_id
    assert set(merged[0].sources) == {"graph_rule", "checkov"}
    assert rule_id in merged[0].ids and checkov_id in merged[0].ids
