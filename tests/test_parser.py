"""Tests for app/parser.py."""

import pytest

from app.parser import MAX_INPUT_BYTES, MAX_NODES, ParserError, parse_architecture


def test_parse_valid_canonical_yaml() -> None:
    raw = """
name: web-app-demo
region: ap-south-1
resources:
  - id: vpc_1
    type: vpc
    props:
      cidr: 10.0.0.0/16
  - id: sub_1
    type: subnet
    in: vpc_1
    props:
      cidr: 10.0.1.0/24
      public: true
  - id: sg_1
    type: security_group
    in: vpc_1
    props:
      ingress:
        - port: 22
          cidr: 0.0.0.0/0
  - id: ec2_a
    type: ec2
    in: sub_1
    uses:
      - sg_1
    props:
      instance_type: t3.micro
      ebs_encrypted: false
  - id: bucket_1
    type: s3
    props:
      versioning: false
      public: false
connections:
  - from: ec2_a
    to: bucket_1
    kind: data
    label: uploads
"""
    arch = parse_architecture(raw)
    assert arch.name == "web-app-demo"
    assert arch.region == "ap-south-1"
    assert len(arch.nodes) == 5
    assert len(arch.edges) == 1
    assert arch.nodes[0].id == "vpc_1"
    assert arch.nodes[1].parent == "vpc_1"
    assert arch.nodes[3].uses == ["sg_1"]


def test_rejection_size_limit() -> None:
    huge_yaml = "a" * (MAX_INPUT_BYTES + 10)
    with pytest.raises(ParserError, match="Input exceeds size cap"):
        parse_architecture(huge_yaml)


def test_rejection_node_count_limit() -> None:
    resources = [
        {"id": f"res_{i}", "type": "s3", "props": {"versioning": True}}
        for i in range(MAX_NODES + 1)
    ]
    payload = {"name": "huge", "region": "us-east-1", "resources": resources}
    with pytest.raises(ParserError, match="Node count exceeds limit"):
        parse_architecture(payload)


def test_rejection_duplicate_node_id() -> None:
    raw = """
name: dupes
region: us-east-1
resources:
  - id: node_1
    type: s3
    props: {}
  - id: node_1
    type: s3
    props: {}
"""
    with pytest.raises(ParserError, match="Duplicate resource id: 'node_1'"):
        parse_architecture(raw)


def test_rejection_invalid_node_id_regex() -> None:
    raw = """
name: bad_id
region: us-east-1
resources:
  - id: 123_invalid
    type: s3
    props: {}
"""
    with pytest.raises(ParserError, match="Validation failed for node"):
        parse_architecture(raw)


def test_rejection_unknown_resource_type() -> None:
    raw = """
name: unknown_type
region: us-east-1
resources:
  - id: lambda_fn
    type: serverless_function
    props: {}
"""
    with pytest.raises(ParserError, match="Validation failed for node"):
        parse_architecture(raw)


def test_rejection_dangling_parent() -> None:
    raw = """
name: dangling_parent
region: us-east-1
resources:
  - id: sub_1
    type: subnet
    in: non_existent_vpc
    props:
      cidr: 10.0.1.0/24
"""
    with pytest.raises(ParserError, match="references non-existent parent"):
        parse_architecture(raw)


def test_rejection_dangling_uses() -> None:
    raw = """
name: dangling_uses
region: us-east-1
resources:
  - id: ec2_1
    type: ec2
    uses:
      - ghost_sg
    props: {}
"""
    with pytest.raises(
        ParserError, match="references non-existent attachment in 'uses'"
    ):
        parse_architecture(raw)


def test_rejection_dangling_connection() -> None:
    raw = """
name: dangling_conn
region: us-east-1
resources:
  - id: s3_1
    type: s3
    props: {}
connections:
  - from: s3_1
    to: ghost_node
    kind: data
"""
    with pytest.raises(ParserError, match="references non-existent target node"):
        parse_architecture(raw)


def test_rejection_containment_cycle() -> None:
    raw = """
name: cyclic_parent
region: us-east-1
resources:
  - id: vpc_1
    type: vpc
    in: sub_1
    props:
      cidr: 10.0.0.0/16
  - id: sub_1
    type: subnet
    in: vpc_1
    props:
      cidr: 10.0.1.0/24
"""
    with pytest.raises(ParserError, match="Cycle detected in parent containment"):
        parse_architecture(raw)


def test_rejection_uses_cycle() -> None:
    raw = """
name: cyclic_uses
region: us-east-1
resources:
  - id: node_a
    type: ec2
    uses:
      - node_b
    props: {}
  - id: node_b
    type: ec2
    uses:
      - node_a
    props: {}
"""
    with pytest.raises(ParserError, match="Cycle detected in 'uses' attachment"):
        parse_architecture(raw)


def test_rejection_unknown_property() -> None:
    raw = """
name: bad_prop
region: us-east-1
resources:
  - id: s3_bad
    type: s3
    props:
      unsupported_key: dangerous_value
"""
    with pytest.raises(ParserError, match="Invalid properties for node 's3_bad'"):
        parse_architecture(raw)


def test_safe_load_enforced() -> None:
    # Attempting to load python object construction should fail safely
    hostile = """
name: exploit
region: us-east-1
resources: !!python/object/apply:os.system ["echo pwned"]
"""
    with pytest.raises(ParserError):
        parse_architecture(hostile)
