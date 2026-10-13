"""Tests for deterministic fix loop, patch generation, diffs, and apply_patch API."""

from pathlib import Path

from fastapi.testclient import TestClient

from app.fix import (
    apply_patch_to_architecture,
    create_patch_for_finding,
    generate_architecture_diff,
)
from app.main import app
from app.models import Architecture, ArchitecturePatch, Finding, Node, PatchOperation

client = TestClient(app)
ARCH_DIR = Path(__file__).parent / "architectures"


def test_fix_recipes_for_all_findings() -> None:
    arch = Architecture(
        name="test_arch",
        region="us-east-1",
        nodes=[
            Node(
                id="sg_1",
                type="security_group",
                props={
                    "ingress": [{"port": 22, "cidr": "0.0.0.0/0", "protocol": "tcp"}]
                },
            ),
            Node(id="ec2_1", type="ec2", props={"ebs_encrypted": False}),
            Node(id="ebs_1", type="ebs", props={"encrypted": False}),
            Node(
                id="rds_1",
                type="rds",
                props={"storage_encrypted": False, "publicly_accessible": True},
            ),
            Node(id="s3_1", type="s3", props={"public": True, "versioning": False}),
        ],
    )

    # 1. SSH fix
    f_ssh = Finding(
        id="RULE_OPEN_SSH",
        ids=["RULE_OPEN_SSH", "CKV_AWS_24"],
        severity="high",
        resource="sg_1",
        title="Open SSH",
        source="graph_rule",
    )
    op_ssh = create_patch_for_finding(arch, f_ssh)
    assert op_ssh is not None
    assert op_ssh.op == "change_props"
    assert op_ssh.props_patch["ingress"][0]["cidr"] == "10.0.0.0/16"

    # 2. EC2 root encryption fix
    f_ec2 = Finding(
        id="RULE_UNENCRYPTED_EC2_ROOT",
        ids=["RULE_UNENCRYPTED_EC2_ROOT", "CKV_AWS_8"],
        severity="medium",
        resource="ec2_1",
        title="Unencrypted EC2 root",
        source="graph_rule",
    )
    op_ec2 = create_patch_for_finding(arch, f_ec2)
    assert op_ec2 is not None
    assert op_ec2.props_patch == {"ebs_encrypted": True}

    # 3. EBS encryption fix
    f_ebs = Finding(
        id="RULE_UNENCRYPTED_EBS",
        ids=["RULE_UNENCRYPTED_EBS", "CKV_AWS_3"],
        severity="medium",
        resource="ebs_1",
        title="Unencrypted EBS",
        source="graph_rule",
    )
    op_ebs = create_patch_for_finding(arch, f_ebs)
    assert op_ebs is not None
    assert op_ebs.props_patch == {"encrypted": True}

    # 4. RDS encryption & public fixes
    f_rds_enc = Finding(
        id="RULE_UNENCRYPTED_RDS",
        ids=["RULE_UNENCRYPTED_RDS", "CKV_AWS_16"],
        severity="medium",
        resource="rds_1",
        title="Unencrypted RDS",
        source="graph_rule",
    )
    op_rds_enc = create_patch_for_finding(arch, f_rds_enc)
    assert op_rds_enc is not None
    assert op_rds_enc.props_patch == {"storage_encrypted": True}

    f_rds_pub = Finding(
        id="RULE_PUBLIC_RDS",
        ids=["RULE_PUBLIC_RDS", "CKV_AWS_17"],
        severity="high",
        resource="rds_1",
        title="Public RDS",
        source="graph_rule",
    )
    op_rds_pub = create_patch_for_finding(arch, f_rds_pub)
    assert op_rds_pub is not None
    assert op_rds_pub.props_patch == {"publicly_accessible": False}

    # 5. S3 public & versioning fixes
    f_s3_pub = Finding(
        id="RULE_PUBLIC_S3",
        ids=["RULE_PUBLIC_S3", "CKV_AWS_20"],
        severity="high",
        resource="s3_1",
        title="Public S3",
        source="graph_rule",
    )
    op_s3_pub = create_patch_for_finding(arch, f_s3_pub)
    assert op_s3_pub is not None
    assert op_s3_pub.props_patch == {"public": False}

    f_s3_ver = Finding(
        id="RULE_S3_NO_VERSIONING",
        ids=["RULE_S3_NO_VERSIONING", "CKV_AWS_21"],
        severity="low",
        resource="s3_1",
        title="No Versioning",
        source="graph_rule",
    )
    op_s3_ver = create_patch_for_finding(arch, f_s3_ver)
    assert op_s3_ver is not None
    assert op_s3_ver.props_patch == {"versioning": True}


def test_immutability_and_patch_application() -> None:
    arch = Architecture(
        name="immutable_test",
        region="us-east-1",
        nodes=[Node(id="ec2_1", type="ec2", props={"ebs_encrypted": False})],
    )

    patch = ArchitecturePatch(
        patch_id="patch-123",
        architecture_id=arch.name,
        operations=[
            PatchOperation(
                op="change_props",
                target_node_id="ec2_1",
                props_patch={"ebs_encrypted": True},
            )
        ],
    )

    patched = apply_patch_to_architecture(arch, patch)
    # Original must be strictly unchanged
    assert arch.nodes[0].props["ebs_encrypted"] is False
    # Patched instance has updated value
    assert patched.nodes[0].props["ebs_encrypted"] is True

    diff = generate_architecture_diff(arch, patched)
    assert "-    ebs_encrypted: false" in diff
    assert "+    ebs_encrypted: true" in diff


def test_fix_api_end_to_end() -> None:
    # 1. Load insecure architecture
    yaml_content = (ARCH_DIR / "insecure_ssh.yaml").read_text(encoding="utf-8")
    resp_create = client.post(
        "/architecture",
        content=yaml_content,
        headers={"Content-Type": "text/yaml"},
    )
    assert resp_create.status_code == 201
    arch_id = resp_create.json()["id"]

    # 2. Check initial findings count
    resp_scan_before = client.post(f"/architecture/{arch_id}/scan")
    assert resp_scan_before.status_code == 200
    before_count = len(resp_scan_before.json()["findings"])
    assert before_count >= 2

    # 3. Call POST /architecture/{id}/fix
    resp_fix = client.post(f"/architecture/{arch_id}/fix")
    assert resp_fix.status_code == 200
    fix_data = resp_fix.json()

    assert "patch_id" in fix_data
    patch_id = fix_data["patch_id"]
    assert fix_data["before_count"] == before_count
    assert fix_data["after_count"] < before_count
    assert fix_data["after_count"] == 0
    assert len(fix_data["fixed_findings"]) >= 2
    assert "diff" in fix_data and len(fix_data["diff"]) > 0
    assert "explanation" in fix_data and len(fix_data["explanation"]) > 0

    # 4. Verify stored architecture is UNCHANGED before apply
    resp_get_before = client.get(f"/architecture/{arch_id}")
    assert resp_get_before.status_code == 200
    nodes_before = {n["id"]: n for n in resp_get_before.json()["nodes"]}
    assert nodes_before["ec2_bastion"]["props"]["ebs_encrypted"] is False

    # 5. Call POST /architecture/{id}/apply_patch
    resp_apply = client.post(
        f"/architecture/{arch_id}/apply_patch",
        json={"patch_id": patch_id},
    )
    assert resp_apply.status_code == 200
    apply_data = resp_apply.json()
    assert apply_data["id"] == arch_id

    # 6. Verify stored architecture IS NOW UPDATED
    resp_get_after = client.get(f"/architecture/{arch_id}")
    assert resp_get_after.status_code == 200
    nodes_after = {n["id"]: n for n in resp_get_after.json()["nodes"]}
    assert nodes_after["ec2_bastion"]["props"]["ebs_encrypted"] is True
    assert nodes_after["sg_open_admin"]["props"]["ingress"][0]["cidr"] == "10.0.0.0/16"

    # 7. Rescan confirms zero violations
    resp_scan_after = client.post(f"/architecture/{arch_id}/scan")
    assert resp_scan_after.status_code == 200
    assert len(resp_scan_after.json()["findings"]) == 0


def test_fix_api_error_cases() -> None:
    # 404 on unknown architecture
    resp_fix = client.post("/architecture/nonexistent-id/fix")
    assert resp_fix.status_code == 404

    # 404 on apply with invalid patch id
    yaml_content = (ARCH_DIR / "secure.yaml").read_text(encoding="utf-8")
    resp_create = client.post(
        "/architecture",
        content=yaml_content,
        headers={"Content-Type": "text/yaml"},
    )
    arch_id = resp_create.json()["id"]

    resp_bad_patch = client.post(
        f"/architecture/{arch_id}/apply_patch",
        json={"patch_id": "nonexistent-patch-id"},
    )
    assert resp_bad_patch.status_code == 404
