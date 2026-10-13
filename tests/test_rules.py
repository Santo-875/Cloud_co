"""Tests for app/rules.py against unit scenarios and sample architectures."""

import json
from pathlib import Path

from app.models import Architecture, Node
from app.parser import parse_architecture
from app.rules import evaluate_graph_rules

ARCH_DIR = Path(__file__).parent / "architectures"


def test_rule_subnet_without_vpc() -> None:
    arch = Architecture(
        name="orphan_subnet",
        region="us-east-1",
        nodes=[
            Node(id="sub_orphan", type="subnet", props={"cidr": "10.0.1.0/24"}),
        ],
    )
    findings = evaluate_graph_rules(arch)
    fids = [f.id for f in findings]
    assert "RULE_SUBNET_NO_VPC" in fids


def test_rule_ec2_outside_subnet() -> None:
    arch = Architecture(
        name="naked_ec2",
        region="us-east-1",
        nodes=[
            Node(id="ec2_orphan", type="ec2", props={"instance_type": "t3.micro"}),
        ],
    )
    findings = evaluate_graph_rules(arch)
    fids = [f.id for f in findings]
    assert "RULE_EC2_NO_SUBNET" in fids
    assert "RULE_EC2_NO_SG" in fids


def test_rule_s3_without_versioning() -> None:
    arch = Architecture(
        name="unversioned_s3",
        region="us-east-1",
        nodes=[
            Node(id="bucket_1", type="s3", props={"versioning": False}),
        ],
    )
    findings = evaluate_graph_rules(arch)
    fids = [f.id for f in findings]
    assert "RULE_S3_NO_VERSIONING" in fids


def test_rule_public_subnet_without_igw() -> None:
    # Public subnet in custom configuration with explicit route table but no IGW
    arch = Architecture(
        name="no_igw_arch",
        region="us-east-1",
        nodes=[
            Node(id="vpc_1", type="vpc", props={"cidr": "10.0.0.0/16"}),
            Node(
                id="sub_pub",
                type="subnet",
                parent="vpc_1",
                props={"cidr": "10.0.1.0/24", "public": True},
            ),
            Node(id="rt_custom", type="route_table", props={}),
        ],
    )
    findings = evaluate_graph_rules(arch)
    fids = [f.id for f in findings]
    assert "RULE_PUBLIC_SUBNET_NO_IGW" in fids


def test_sample_architectures_against_expectations() -> None:
    samples = ["secure", "insecure_ssh", "public_rds"]
    for sample in samples:
        yaml_path = ARCH_DIR / f"{sample}.yaml"
        expected_path = ARCH_DIR / f"{sample}.expected.json"

        assert yaml_path.exists(), f"Missing sample file {yaml_path}"
        assert expected_path.exists(), f"Missing expectation file {expected_path}"

        raw_yaml = yaml_path.read_text(encoding="utf-8")
        arch = parse_architecture(raw_yaml)
        findings = evaluate_graph_rules(arch)
        actual_fids = sorted({f.id for f in findings})

        expected_data = json.loads(expected_path.read_text(encoding="utf-8"))
        expected_fids = sorted(expected_data["finding_ids"])

        assert (
            actual_fids == expected_fids
        ), f"Sample '{sample}' findings mismatch: actual {actual_fids} != expected {expected_fids}"
