"""Tests for FastAPI endpoints, HTTP codes, and rate limiting."""

from fastapi.testclient import TestClient

from app.config import settings
from app.main import _chat_rate_limits, app

client = TestClient(app)

SAMPLE_YAML = """
name: test-app
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
      public: false
  - id: ec2_1
    type: ec2
    in: sub_1
    props:
      instance_type: t3.micro
      ebs_encrypted: true
"""


def test_health_endpoint() -> None:
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "version": "0.1.0"}


def test_architecture_crud_flow() -> None:
    # 1. POST /architecture
    post_resp = client.post(
        "/architecture",
        content=SAMPLE_YAML.encode("utf-8"),
        headers={"Content-Type": "text/yaml"},
    )
    assert post_resp.status_code == 201
    data = post_resp.json()
    arch_id = data["id"]
    assert data["name"] == "test-app"
    assert data["nodes_count"] == 3

    # 2. GET /architecture/{id}
    get_resp = client.get(f"/architecture/{arch_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["name"] == "test-app"

    # 3. GET /architecture/{id}/graph
    graph_resp = client.get(f"/architecture/{arch_id}/graph")
    assert graph_resp.status_code == 200
    assert "nodes" in graph_resp.json()
    assert "clusters" in graph_resp.json()

    # 4. POST /architecture/{id}/terraform
    tf_resp = client.post(f"/architecture/{arch_id}/terraform")
    assert tf_resp.status_code == 200
    assert "main.tf" in tf_resp.json()["files"]

    # 5. POST /architecture/{id}/scan
    scan_resp = client.post(f"/architecture/{arch_id}/scan")
    assert scan_resp.status_code == 200
    assert "findings" in scan_resp.json()
    assert "scanners_run" in scan_resp.json()

    # 6. GET /architecture/{id}/cost
    cost_resp = client.get(f"/architecture/{arch_id}/cost")
    assert cost_resp.status_code == 200
    assert "total_monthly_usd" in cost_resp.json()


def test_architecture_rejection() -> None:
    bad_yaml = "invalid: yaml: [["
    resp = client.post(
        "/architecture",
        content=bad_yaml.encode("utf-8"),
        headers={"Content-Type": "text/yaml"},
    )
    assert resp.status_code == 400


def test_architecture_not_found() -> None:
    resp = client.get("/architecture/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404


def test_chat_rate_limiting() -> None:
    # Create architecture
    post_resp = client.post(
        "/architecture",
        content=SAMPLE_YAML.encode("utf-8"),
        headers={"Content-Type": "text/yaml"},
    )
    arch_id = post_resp.json()["id"]

    # Clear rate limit counter
    _chat_rate_limits.clear()

    # Send up to limit (10 requests)
    for _ in range(settings.chat_rate_limit_per_minute):
        res = client.post(
            "/chat",
            json={
                "architecture_id": arch_id,
                "message": "Explain architecture",
                "mode": "explain_architecture",
            },
        )
        assert res.status_code == 200

    # 11th request must fail with 429
    res_exceeded = client.post(
        "/chat",
        json={
            "architecture_id": arch_id,
            "message": "Explain architecture",
            "mode": "explain_architecture",
        },
    )
    assert res_exceeded.status_code == 429
    assert "Rate limit exceeded" in res_exceeded.json()["detail"]

    # Clean up state
    _chat_rate_limits.clear()
