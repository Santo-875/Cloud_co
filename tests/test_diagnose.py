"""Tests for deterministic network reachability diagnosis and blocker ranking."""

from pathlib import Path

from fastapi.testclient import TestClient

from app.diagnose import (
    diagnose_reachability,
    extract_nodes_from_query,
    infer_target_port,
)
from app.main import app
from app.models import Architecture, Edge, Node

client = TestClient(app)
ARCH_DIR = Path(__file__).parent / "architectures"


def test_extract_nodes_from_query() -> None:
    nodes = [
        Node(id="ec2a", type="ec2"),
        Node(id="rds1", type="rds"),
        Node(id="s3_bucket", type="s3"),
    ]
    src, tgt = extract_nodes_from_query("why can't ec2a reach rds1", nodes)
    assert src == "ec2a"
    assert tgt == "rds1"

    src2, tgt2 = extract_nodes_from_query(
        "is ec2a able to connect to s3_bucket?", nodes
    )
    assert src2 == "ec2a"
    assert tgt2 == "s3_bucket"


def test_infer_default_ports() -> None:
    rds_pg = Node(id="rds_pg", type="rds", props={"engine": "postgres"})
    rds_mysql = Node(id="rds_my", type="rds", props={"engine": "mysql"})
    ec2_node = Node(id="ec2", type="ec2")

    assert infer_target_port(rds_pg) == 5432
    assert infer_target_port(rds_mysql) == 3306
    assert infer_target_port(ec2_node) == 80
    assert infer_target_port(ec2_node, explicit_port=8080) == 8080


def test_diagnose_security_group_ingress_blocked() -> None:
    arch = Architecture(
        name="reachability_test",
        region="us-east-1",
        nodes=[
            Node(id="vpc_1", type="vpc", props={"cidr": "10.0.0.0/16"}),
            Node(
                id="sub_1", type="subnet", parent="vpc_1", props={"cidr": "10.0.1.0/24"}
            ),
            Node(
                id="sub_2", type="subnet", parent="vpc_1", props={"cidr": "10.0.2.0/24"}
            ),
            Node(
                id="sg_ec2",
                type="security_group",
                parent="vpc_1",
                props={"ingress": [], "egress": []},
            ),
            Node(
                id="sg_rds",
                type="security_group",
                parent="vpc_1",
                props={
                    # Ingress only for HTTP (80), not database port (5432)
                    "ingress": [{"port": 80, "cidr": "10.0.0.0/16", "protocol": "tcp"}],
                    "egress": [],
                },
            ),
            Node(id="ec2_client", type="ec2", parent="sub_1", uses=["sg_ec2"]),
            Node(
                id="rds_target",
                type="rds",
                parent="sub_2",
                uses=["sg_rds"],
                props={"engine": "postgres"},
            ),
        ],
    )

    resp = diagnose_reachability(arch, question="why can't ec2_client reach rds_target")
    assert resp.reachable is False
    assert resp.source == "ec2_client"
    assert resp.target == "rds_target"
    assert len(resp.blockers) >= 1

    top_blocker = resp.blockers[0]
    assert top_blocker.category == "security_group_ingress"
    assert "port 5432" in top_blocker.summary
    assert resp.graph_evidence["target_port"] == 5432
    assert resp.graph_evidence["source_vpc"] == "vpc_1"
    assert resp.graph_evidence["target_vpc"] == "vpc_1"


def test_diagnose_vpc_boundary_blocker() -> None:
    arch = Architecture(
        name="multi_vpc_test",
        region="us-east-1",
        nodes=[
            Node(id="vpc_a", type="vpc", props={"cidr": "10.0.0.0/16"}),
            Node(id="vpc_b", type="vpc", props={"cidr": "172.16.0.0/16"}),
            Node(
                id="sub_a", type="subnet", parent="vpc_a", props={"cidr": "10.0.1.0/24"}
            ),
            Node(
                id="sub_b",
                type="subnet",
                parent="vpc_b",
                props={"cidr": "172.16.1.0/24"},
            ),
            Node(id="ec2_a", type="ec2", parent="sub_a"),
            Node(id="ec2_b", type="ec2", parent="sub_b"),
        ],
    )

    resp = diagnose_reachability(arch, question="can ec2_a connect to ec2_b")
    assert resp.reachable is False
    categories = [b.category for b in resp.blockers]
    assert "vpc_boundary" in categories


def test_diagnose_reachability_allowed() -> None:
    arch = Architecture(
        name="open_test",
        region="us-east-1",
        nodes=[
            Node(id="vpc_1", type="vpc", props={"cidr": "10.0.0.0/16"}),
            Node(
                id="sub_1", type="subnet", parent="vpc_1", props={"cidr": "10.0.1.0/24"}
            ),
            Node(
                id="sub_2", type="subnet", parent="vpc_1", props={"cidr": "10.0.2.0/24"}
            ),
            Node(
                id="sg_client",
                type="security_group",
                parent="vpc_1",
                props={"ingress": [], "egress": []},
            ),
            Node(
                id="sg_server",
                type="security_group",
                parent="vpc_1",
                props={
                    "ingress": [
                        {"port": 5432, "cidr": "10.0.0.0/16", "protocol": "tcp"}
                    ],
                    "egress": [],
                },
            ),
            Node(id="ec2_client", type="ec2", parent="sub_1", uses=["sg_client"]),
            Node(
                id="rds_server",
                type="rds",
                parent="sub_2",
                uses=["sg_server"],
                props={"engine": "postgres"},
            ),
        ],
        edges=[Edge(source="ec2_client", target="rds_server", kind="network")],
    )

    resp = diagnose_reachability(arch, question="verify ec2_client to rds_server")
    assert resp.reachable is True
    assert len(resp.blockers) == 0


def test_diagnose_api_endpoint() -> None:
    # 1. Upload sample architecture
    yaml_content = (ARCH_DIR / "insecure_ssh.yaml").read_text(encoding="utf-8")
    resp_create = client.post(
        "/architecture",
        content=yaml_content,
        headers={"Content-Type": "text/yaml"},
    )
    assert resp_create.status_code == 201
    arch_id = resp_create.json()["id"]

    # 2. Call POST /architecture/{id}/diagnose
    resp_diag = client.post(
        f"/architecture/{arch_id}/diagnose",
        json={"question": "why can't ec2_bastion reach rds_db"},
    )
    assert resp_diag.status_code == 200
    diag_data = resp_diag.json()

    assert "reachable" in diag_data
    assert diag_data["source"] == "ec2_bastion"
    assert "blockers" in diag_data
    assert "graph_evidence" in diag_data
    assert "explanation" in diag_data
    assert len(diag_data["explanation"]) > 0

    # 3. 404 for unknown architecture
    resp_not_found = client.post(
        "/architecture/unknown-arch-id/diagnose",
        json={"question": "why can't a reach b"},
    )
    assert resp_not_found.status_code == 404
