"""Deterministic fix recipes, patch generation, application, and diffs."""

import difflib
import uuid
from copy import deepcopy
from typing import Any

import yaml

from app.models import Architecture, ArchitecturePatch, Finding, Node, PatchOperation


def create_patch_for_finding(
    arch: Architecture, finding: Finding
) -> PatchOperation | None:
    """Generate deterministic patch operation for a given finding."""
    check_str = f"{finding.id} {finding.title} {' '.join(finding.ids)}".lower()

    # 1. Open SSH: Restrict port 22 CIDR on security group to trusted RFC1918 range
    if (
        "ckv_aws_24" in check_str
        or "open_ssh" in check_str
        or "ssh" in check_str
        or "22" in check_str
    ):
        node = next((n for n in arch.nodes if n.id == finding.resource), None)
        if node and node.type == "security_group":
            ingress = deepcopy(node.props.get("ingress", []))
            modified = False
            for rule in ingress:
                if (rule.get("port") == 22 or rule.get("to_port") == 22) and (
                    rule.get("cidr") == "0.0.0.0/0"
                ):
                    rule["cidr"] = "10.0.0.0/16"
                    modified = True
            if modified:
                return PatchOperation(
                    op="change_props",
                    target_node_id=node.id,
                    props_patch={"ingress": ingress},
                )

    # 2. Open RDP: Restrict port 3389
    if "rdp" in check_str or "3389" in check_str:
        node = next((n for n in arch.nodes if n.id == finding.resource), None)
        if node and node.type == "security_group":
            ingress = deepcopy(node.props.get("ingress", []))
            modified = False
            for rule in ingress:
                if (rule.get("port") == 3389 or rule.get("to_port") == 3389) and (
                    rule.get("cidr") == "0.0.0.0/0"
                ):
                    rule["cidr"] = "10.0.0.0/16"
                    modified = True
            if modified:
                return PatchOperation(
                    op="change_props",
                    target_node_id=node.id,
                    props_patch={"ingress": ingress},
                )

    # 3. Unencrypted EC2 root: enable ebs_encrypted
    if "ckv_aws_8" in check_str or "unencrypted_ec2" in check_str:
        node = next((n for n in arch.nodes if n.id == finding.resource), None)
        if node and node.type == "ec2":
            return PatchOperation(
                op="change_props",
                target_node_id=node.id,
                props_patch={"ebs_encrypted": True},
            )

    # 4. Unencrypted EBS volume: enable encrypted
    if "ckv_aws_3" in check_str or "unencrypted_ebs" in check_str:
        node = next((n for n in arch.nodes if n.id == finding.resource), None)
        if node and node.type == "ebs":
            return PatchOperation(
                op="change_props",
                target_node_id=node.id,
                props_patch={"encrypted": True},
            )

    # 5. Unencrypted RDS storage: enable storage_encrypted
    if "ckv_aws_16" in check_str or "unencrypted_rds" in check_str:
        node = next((n for n in arch.nodes if n.id == finding.resource), None)
        if node and node.type == "rds":
            return PatchOperation(
                op="change_props",
                target_node_id=node.id,
                props_patch={"storage_encrypted": True},
            )

    # 6. Public RDS instance: disable publicly_accessible
    if (
        "ckv_aws_17" in check_str
        or "public_rds" in check_str
        or ("rds" in check_str and "public" in check_str)
    ):
        node = next((n for n in arch.nodes if n.id == finding.resource), None)
        if node and node.type == "rds":
            return PatchOperation(
                op="change_props",
                target_node_id=node.id,
                props_patch={"publicly_accessible": False},
            )

    # 7. Public S3 bucket: disable public
    if (
        "ckv_aws_20" in check_str
        or "public_s3" in check_str
        or ("s3" in check_str and "public" in check_str)
    ):
        node = next((n for n in arch.nodes if n.id == finding.resource), None)
        if node and node.type == "s3":
            return PatchOperation(
                op="change_props",
                target_node_id=node.id,
                props_patch={"public": False},
            )

    # 8. S3 without versioning: enable versioning
    if "ckv_aws_21" in check_str or "versioning" in check_str:
        node = next((n for n in arch.nodes if n.id == finding.resource), None)
        if node and node.type == "s3":
            return PatchOperation(
                op="change_props",
                target_node_id=node.id,
                props_patch={"versioning": True},
            )

    return None


def generate_patch(
    arch: Architecture,
    findings: list[Finding],
    filter_finding_ids: list[str] | None = None,
) -> tuple[ArchitecturePatch, list[str]]:
    """Generate structured ArchitecturePatch and return list of resolved finding ids."""
    operations: list[PatchOperation] = []
    fixed_ids: list[str] = []

    # Map to track props updates per target node so multiple changes are merged
    merged_props_by_node: dict[str, dict[str, Any]] = {}

    for finding in findings:
        if (
            filter_finding_ids
            and finding.id not in filter_finding_ids
            and not any(i in filter_finding_ids for i in finding.ids)
        ):
            continue

        op = create_patch_for_finding(arch, finding)
        if op:
            if op.op == "change_props":
                merged_props_by_node.setdefault(op.target_node_id, {}).update(
                    op.props_patch
                )
            else:
                operations.append(op)
            fixed_ids.append(finding.id)

    for node_id, props in merged_props_by_node.items():
        operations.append(
            PatchOperation(
                op="change_props",
                target_node_id=node_id,
                props_patch=props,
            )
        )

    patch = ArchitecturePatch(
        patch_id=str(uuid.uuid4()),
        architecture_id=arch.name,
        operations=operations,
    )
    return patch, fixed_ids


def apply_patch_to_architecture(
    arch: Architecture, patch: ArchitecturePatch
) -> Architecture:
    """Apply patch operations to produce a new patched Architecture without modifying original."""
    new_nodes_map: dict[str, Node] = {n.id: deepcopy(n) for n in arch.nodes}
    new_edges = [deepcopy(e) for e in arch.edges]

    for op in patch.operations:
        if op.op == "change_props":
            if op.target_node_id in new_nodes_map:
                target = new_nodes_map[op.target_node_id]
                updated_props = deepcopy(target.props)
                updated_props.update(op.props_patch)
                new_nodes_map[op.target_node_id] = Node(
                    id=target.id,
                    type=target.type,
                    parent=target.parent,
                    uses=deepcopy(target.uses),
                    props=updated_props,
                )
        elif op.op == "add_node" and op.node:
            if op.node.id not in new_nodes_map:
                new_nodes_map[op.node.id] = deepcopy(op.node)
        elif op.op == "remove_node":
            new_nodes_map.pop(op.target_node_id, None)
            new_edges = [
                e
                for e in new_edges
                if e.source != op.target_node_id and e.target != op.target_node_id
            ]

    return Architecture(
        name=arch.name,
        region=arch.region,
        nodes=list(new_nodes_map.values()),
        edges=new_edges,
    )


def architecture_to_clean_yaml(arch: Architecture) -> str:
    """Export architecture to canonical YAML representation for diffing."""
    data: dict[str, Any] = {
        "name": arch.name,
        "region": arch.region,
        "resources": [
            {
                "id": n.id,
                "type": n.type,
                **({"in": n.parent} if n.parent else {}),
                **({"uses": n.uses} if n.uses else {}),
                "props": n.props,
            }
            for n in arch.nodes
        ],
    }
    if arch.edges:
        data["connections"] = [
            {
                "from": e.source,
                "to": e.target,
                "kind": e.kind,
                **({"label": e.label} if e.label else {}),
            }
            for e in arch.edges
        ]
    return yaml.dump(data, sort_keys=False, default_flow_style=False)


def generate_architecture_diff(before: Architecture, after: Architecture) -> str:
    """Generate unified readable diff between original and patched architectures."""
    before_lines = architecture_to_clean_yaml(before).splitlines(keepends=True)
    after_lines = architecture_to_clean_yaml(after).splitlines(keepends=True)
    diff = difflib.unified_diff(
        before_lines,
        after_lines,
        fromfile=f"a/{before.name}.yaml (original)",
        tofile=f"b/{after.name}.yaml (patched)",
        lineterm="",
    )
    return "\n".join(diff)
