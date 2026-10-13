"""Tests for app/models.py."""

import pytest
from pydantic import ValidationError

from app.models import Architecture, Edge, Finding, Node


def test_node_id_regex_validation() -> None:
    # Valid IDs
    n1 = Node(id="vpc_1", type="vpc", props={"cidr": "10.0.0.0/16"})
    assert n1.id == "vpc_1"

    n2 = Node(id="a", type="vpc", props={"cidr": "10.0.0.0/16"})
    assert n2.id == "a"

    # Invalid IDs
    with pytest.raises(ValidationError):
        Node(id="1vpc", type="vpc")  # starts with digit

    with pytest.raises(ValidationError):
        Node(id="VPC_UPPER", type="vpc")  # uppercase

    with pytest.raises(ValidationError):
        Node(id="vpc-dash", type="vpc")  # dash not allowed

    with pytest.raises(ValidationError):
        Node(id="a" * 45, type="vpc")  # too long (> 41 chars)


def test_typed_props_validation_vpc() -> None:
    node = Node(id="my_vpc", type="vpc", props={"cidr": "10.0.0.0/16"})
    validated = node.validate_props()
    assert validated.cidr == "10.0.0.0/16"

    # Invalid CIDR prefix
    bad_node = Node(id="bad_vpc", type="vpc", props={"cidr": "10.0.0.0/8"})
    with pytest.raises(ValueError):
        bad_node.validate_props()

    # Unknown property rejected (extra="forbid")
    unknown_prop_node = Node(
        id="bad_vpc", type="vpc", props={"cidr": "10.0.0.0/16", "foo": "bar"}
    )
    with pytest.raises(ValidationError):
        unknown_prop_node.validate_props()


def test_typed_props_validation_ec2() -> None:
    node = Node(
        id="web_srv",
        type="ec2",
        props={"instance_type": "t3.micro", "ebs_encrypted": True},
    )
    validated = node.validate_props()
    assert validated.instance_type == "t3.micro"

    # Hostile / invalid instance type regex
    bad_node = Node(
        id="bad_ec2",
        type="ec2",
        props={"instance_type": "invalid; rm -rf /"},
    )
    with pytest.raises(ValueError):
        bad_node.validate_props()


def test_finding_multi_source_fields() -> None:
    finding = Finding(
        id="RULE_OPEN_SSH",
        ids=["RULE_OPEN_SSH", "CKV_AWS_24"],
        severity="high",
        resource="sg_1",
        title="Port 22 open to world",
        source="graph_rule",
        sources=["graph_rule", "checkov"],
        fix_hint="Restrict port 22",
    )
    assert finding.source == "graph_rule"
    assert "checkov" in finding.sources
    assert len(finding.ids) == 2


def test_architecture_structure() -> None:
    arch = Architecture(
        name="test_arch",
        region="us-east-1",
        nodes=[
            Node(id="v1", type="vpc", props={"cidr": "10.0.0.0/16"}),
        ],
        edges=[
            Edge(source="v1", target="v1", kind="network"),
        ],
    )
    assert arch.name == "test_arch"
    assert len(arch.nodes) == 1
