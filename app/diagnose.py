"""Deterministic network reachability and blocker diagnostic engine."""

import re
from typing import Any

from app.models import Architecture, DiagnoseResponse, DiagnosticBlocker, Node


def extract_nodes_from_query(
    question: str, nodes: list[Node]
) -> tuple[str | None, str | None]:
    """Extract source and target node identifiers mentioned in natural language inquiry."""
    node_ids = {n.id.lower(): n.id for n in nodes}
    tokens = re.findall(r"[a-zA-Z0-9_]+", question.lower())

    matched: list[str] = []
    for token in tokens:
        if token in node_ids and node_ids[token] not in matched:
            matched.append(node_ids[token])

    if len(matched) >= 2:
        return matched[0], matched[1]
    if len(matched) == 1:
        return matched[0], None
    return None, None


def resolve_node_containment(
    node: Node, nodes_map: dict[str, Node]
) -> tuple[str | None, str | None]:
    """Resolve subnet ID and VPC ID for a given node by walking parent references."""
    subnet_id = None
    vpc_id = None

    curr: Node | None = node
    while curr and curr.parent:
        parent_node = nodes_map.get(curr.parent)
        if not parent_node:
            break
        if parent_node.type == "subnet" and not subnet_id:
            subnet_id = parent_node.id
        elif parent_node.type == "vpc" and not vpc_id:
            vpc_id = parent_node.id
        curr = parent_node

    return subnet_id, vpc_id


def infer_target_port(target_node: Node, explicit_port: int | None = None) -> int:
    """Infer destination port based on node type and engine properties."""
    if explicit_port is not None:
        return explicit_port

    if target_node.type == "rds":
        engine = str(target_node.props.get("engine", "postgres")).lower()
        if "mysql" in engine or "mariadb" in engine or "aurora-mysql" in engine:
            return 3306
        return 5432  # Default PostgreSQL
    if target_node.type == "ec2":
        return 80
    if target_node.type == "s3":
        return 443
    return 443


def diagnose_reachability(
    arch: Architecture,
    question: str,
    source_id: str | None = None,
    target_id: str | None = None,
    port: int | None = None,
) -> DiagnoseResponse:
    """Perform deterministic reachability analysis over subnets, security groups, routes, and connections."""
    nodes_map = {n.id: n for n in arch.nodes}

    # 1. Resolve source and target
    if not source_id or not target_id:
        q_src, q_tgt = extract_nodes_from_query(question, arch.nodes)
        source_id = source_id or q_src
        target_id = target_id or q_tgt

    if not source_id or not target_id:
        return DiagnoseResponse(
            reachable=False,
            source=source_id or "unknown",
            target=target_id or "unknown",
            blockers=[
                DiagnosticBlocker(
                    rank=1,
                    category="unknown_resource",
                    summary=f"Could not identify both source and target in query '{question}'. Available nodes: {list(nodes_map.keys())}",
                    evidence={
                        "query": question,
                        "available_nodes": list(nodes_map.keys()),
                    },
                )
            ],
            graph_evidence={},
            explanation="Unable to analyze reachability: please specify valid source and target resource IDs.",
        )

    source_node = nodes_map.get(source_id)
    target_node = nodes_map.get(target_id)

    if not source_node or not target_node:
        missing = []
        if not source_node:
            missing.append(source_id)
        if not target_node:
            missing.append(target_id)
        return DiagnoseResponse(
            reachable=False,
            source=source_id,
            target=target_id,
            blockers=[
                DiagnosticBlocker(
                    rank=1,
                    category="unknown_resource",
                    summary=f"Resource(s) {missing} do not exist in the architecture graph.",
                    evidence={"missing": missing},
                )
            ],
            graph_evidence={},
            explanation=f"Resource lookup failure: {', '.join(missing)} was not found.",
        )

    target_port = infer_target_port(target_node, port)

    # 2. Gather Topology Evidence
    src_subnet_id, src_vpc_id = resolve_node_containment(source_node, nodes_map)
    tgt_subnet_id, tgt_vpc_id = resolve_node_containment(target_node, nodes_map)

    src_subnet = nodes_map.get(src_subnet_id) if src_subnet_id else None
    tgt_subnet = nodes_map.get(tgt_subnet_id) if tgt_subnet_id else None

    # Collect security groups used by source and target
    src_sgs = [
        nodes_map[sg_id]
        for sg_id in source_node.uses
        if sg_id in nodes_map and nodes_map[sg_id].type == "security_group"
    ]
    tgt_sgs = [
        nodes_map[sg_id]
        for sg_id in target_node.uses
        if sg_id in nodes_map and nodes_map[sg_id].type == "security_group"
    ]

    has_direct_edge = any(
        (e.source == source_id and e.target == target_id)
        or (e.source == target_id and e.target == source_id)
        for e in arch.edges
    )

    graph_evidence: dict[str, Any] = {
        "source_id": source_id,
        "source_type": source_node.type,
        "source_subnet": src_subnet_id,
        "source_vpc": src_vpc_id,
        "source_security_groups": [sg.id for sg in src_sgs],
        "target_id": target_id,
        "target_type": target_node.type,
        "target_subnet": tgt_subnet_id,
        "target_vpc": tgt_vpc_id,
        "target_security_groups": [sg.id for sg in tgt_sgs],
        "target_port": target_port,
        "direct_edge": has_direct_edge,
    }

    blockers: list[DiagnosticBlocker] = []
    rank = 1

    # 3. VPC Boundary Check
    if src_vpc_id and tgt_vpc_id and src_vpc_id != tgt_vpc_id:
        blockers.append(
            DiagnosticBlocker(
                rank=rank,
                category="vpc_boundary",
                summary=f"VPC Boundary Mismatch: Source '{source_id}' is in VPC '{src_vpc_id}' while Target '{target_id}' is in VPC '{tgt_vpc_id}'. No VPC peering or transit gateway is configured.",
                evidence={"source_vpc": src_vpc_id, "target_vpc": tgt_vpc_id},
            )
        )
        rank += 1

    # 4. Target Security Group Ingress Check
    # Traffic must be explicitly allowed by at least one target SG ingress rule on target_port
    if tgt_sgs:
        ingress_allowed = False
        allowed_rules = []
        for sg in tgt_sgs:
            for rule in sg.props.get("ingress", []):
                rule_from = rule.get("port", 0)
                rule_to = rule.get("to_port", rule_from)
                if rule_from <= target_port <= rule_to:
                    ingress_allowed = True
                    allowed_rules.append({"sg_id": sg.id, "rule": rule})

        if not ingress_allowed:
            blockers.append(
                DiagnosticBlocker(
                    rank=rank,
                    category="security_group_ingress",
                    summary=f"Security Group Ingress Denied: Target security group(s) {[sg.id for sg in tgt_sgs]} have no ingress rule allowing port {target_port} traffic from source '{source_id}'.",
                    evidence={
                        "target_security_groups": [sg.id for sg in tgt_sgs],
                        "expected_port": target_port,
                        "checked_rules": [
                            r for sg in tgt_sgs for r in sg.props.get("ingress", [])
                        ],
                    },
                )
            )
            rank += 1
    elif target_node.type in ("ec2", "rds"):
        blockers.append(
            DiagnosticBlocker(
                rank=rank,
                category="security_group_ingress",
                summary=f"Missing Security Group: Target '{target_id}' has no security group attached, rejecting incoming connections.",
                evidence={"target_node": target_id},
            )
        )
        rank += 1

    # 5. Source Security Group Egress Check
    if src_sgs:
        egress_blocked = True
        for sg in src_sgs:
            egress_rules = sg.props.get("egress", [])
            if not egress_rules:
                # Default AWS SG allows all outbound traffic unless restricted
                egress_blocked = False
                break
            for rule in egress_rules:
                rule_from = rule.get("port", 0)
                rule_to = rule.get("to_port", rule_from if rule_from else 65535)
                # Matches all ports (0) or range enclosing target_port
                if rule_from == 0 or (rule_from <= target_port <= rule_to):
                    egress_blocked = False
                    break

        if egress_blocked:
            blockers.append(
                DiagnosticBlocker(
                    rank=rank,
                    category="security_group_egress",
                    summary=f"Security Group Egress Blocked: Source security group(s) {[sg.id for sg in src_sgs]} egress rules restrict outbound traffic on port {target_port}.",
                    evidence={
                        "source_security_groups": [sg.id for sg in src_sgs],
                        "target_port": target_port,
                    },
                )
            )
            rank += 1

    # 6. Subnet Placement & Routing
    if src_subnet and tgt_subnet and src_vpc_id == tgt_vpc_id:
        # Same VPC subnets communicate by default via local route unless network ACL or public isolation occurs
        pass
    elif not src_subnet and source_node.type in ("ec2", "rds"):
        blockers.append(
            DiagnosticBlocker(
                rank=rank,
                category="subnet_routing",
                summary=f"Unplaced Resource: Source '{source_id}' is not placed inside any subnet.",
                evidence={"source_id": source_id},
            )
        )
        rank += 1

    # 7. Missing Connection Edge
    if not has_direct_edge and not blockers:
        # Graph doesn't reflect an explicit logical connection
        graph_evidence["missing_edge_hint"] = (
            f"No explicit edge from '{source_id}' to '{target_id}' defined in architecture."
        )

    reachable = len(blockers) == 0

    return DiagnoseResponse(
        reachable=reachable,
        source=source_id,
        target=target_id,
        blockers=blockers,
        graph_evidence=graph_evidence,
        explanation="",  # To be filled by LLM explainer
    )
