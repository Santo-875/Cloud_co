"""Deterministic graph security and topology rules."""

from app.graph import ArchitectureGraph
from app.models import Architecture, Finding


def rule_subnet_without_vpc(graph: ArchitectureGraph) -> list[Finding]:
    """Flag subnets that do not have a VPC parent."""
    findings: list[Finding] = []
    for node in graph.architecture.nodes:
        if node.type == "subnet":
            parent = graph.get_parent(node.id)
            if not parent or parent.type != "vpc":
                fid = "RULE_SUBNET_NO_VPC"
                findings.append(
                    Finding(
                        id=fid,
                        ids=[fid],
                        severity="high",
                        resource=node.id,
                        title=f"Subnet '{node.id}' has no enclosing VPC parent",
                        source="graph_rule",
                        sources=["graph_rule"],
                        fix_hint=f"Assign 'in: <vpc_id>' to subnet '{node.id}'",
                    )
                )
    return findings


def rule_ec2_outside_subnet(graph: ArchitectureGraph) -> list[Finding]:
    """Flag EC2 instances that are placed outside of any subnet."""
    findings: list[Finding] = []
    for node in graph.architecture.nodes:
        if node.type == "ec2":
            parent = graph.get_parent(node.id)
            if not parent or parent.type != "subnet":
                fid = "RULE_EC2_NO_SUBNET"
                findings.append(
                    Finding(
                        id=fid,
                        ids=[fid],
                        severity="high",
                        resource=node.id,
                        title=f"EC2 instance '{node.id}' is not contained within a subnet",
                        source="graph_rule",
                        sources=["graph_rule"],
                        fix_hint=f"Set 'in: <subnet_id>' on EC2 instance '{node.id}'",
                    )
                )
    return findings


def rule_ec2_without_security_group(graph: ArchitectureGraph) -> list[Finding]:
    """Flag EC2 instances that do not attach any security group."""
    findings: list[Finding] = []
    for node in graph.architecture.nodes:
        if node.type == "ec2":
            used_sgs = [
                u for u in graph.get_used_nodes(node.id) if u.type == "security_group"
            ]
            if not used_sgs:
                fid = "RULE_EC2_NO_SG"
                findings.append(
                    Finding(
                        id=fid,
                        ids=[fid],
                        severity="high",
                        resource=node.id,
                        title=f"EC2 instance '{node.id}' has no associated security group",
                        source="graph_rule",
                        sources=["graph_rule"],
                        fix_hint=f"Attach a security group to '{node.id}' via the 'uses' field",
                    )
                )
    return findings


def rule_open_ssh_or_rdp(graph: ArchitectureGraph) -> list[Finding]:
    """Flag security groups that permit ingress port 22 or 3389 from 0.0.0.0/0."""
    findings: list[Finding] = []
    for node in graph.architecture.nodes:
        if node.type == "security_group":
            ingress_rules = node.props.get("ingress", [])
            for r in ingress_rules:
                port = (
                    r.get("port") if isinstance(r, dict) else getattr(r, "port", None)
                )
                to_port = (
                    r.get("to_port")
                    if isinstance(r, dict)
                    else getattr(r, "to_port", None)
                )
                cidr = (
                    r.get("cidr") if isinstance(r, dict) else getattr(r, "cidr", None)
                )

                ports = {port}
                if to_port is not None and port is not None:
                    ports.update(range(port, min(to_port + 1, port + 100)))

                if (22 in ports or 3389 in ports) and cidr == "0.0.0.0/0":
                    threat_port = 22 if 22 in ports else 3389
                    proto_name = "SSH" if threat_port == 22 else "RDP"
                    fid = f"RULE_OPEN_{proto_name}"
                    findings.append(
                        Finding(
                            id=fid,
                            ids=[fid, "CKV_AWS_24"],
                            severity="high",
                            resource=node.id,
                            title=f"Security group '{node.id}' permits unrestricted {proto_name} (port {threat_port}) from 0.0.0.0/0",
                            source="graph_rule",
                            sources=["graph_rule"],
                            fix_hint=f"Restrict port {threat_port} ingress on '{node.id}' to a trusted bastion or corporate CIDR",
                        )
                    )
    return findings


def rule_public_s3_or_public_rds(graph: ArchitectureGraph) -> list[Finding]:
    """Flag publicly accessible S3 buckets or RDS instances."""
    findings: list[Finding] = []
    for node in graph.architecture.nodes:
        if node.type == "s3" and node.props.get("public") is True:
            fid = "RULE_PUBLIC_S3"
            findings.append(
                Finding(
                    id=fid,
                    ids=[fid, "CKV_AWS_20"],
                    severity="high",
                    resource=node.id,
                    title=f"S3 bucket '{node.id}' is configured with public access enabled",
                    source="graph_rule",
                    sources=["graph_rule"],
                    fix_hint=f"Set 'public: false' on S3 bucket '{node.id}' and enable Block Public Access",
                )
            )
        elif node.type == "rds" and node.props.get("publicly_accessible") is True:
            fid = "RULE_PUBLIC_RDS"
            findings.append(
                Finding(
                    id=fid,
                    ids=[fid, "CKV_AWS_17"],
                    severity="high",
                    resource=node.id,
                    title=f"RDS instance '{node.id}' is publicly accessible from the internet",
                    source="graph_rule",
                    sources=["graph_rule"],
                    fix_hint=f"Set 'publicly_accessible: false' on RDS instance '{node.id}'",
                )
            )
    return findings


def rule_unencrypted_storage(graph: ArchitectureGraph) -> list[Finding]:
    """Flag unencrypted EBS volumes or unencrypted RDS storage."""
    findings: list[Finding] = []
    for node in graph.architecture.nodes:
        if node.type == "ebs" and node.props.get("encrypted") is False:
            fid = "RULE_UNENCRYPTED_EBS"
            findings.append(
                Finding(
                    id=fid,
                    ids=[fid, "CKV_AWS_3"],
                    severity="medium",
                    resource=node.id,
                    title=f"EBS volume '{node.id}' does not have storage encryption enabled",
                    source="graph_rule",
                    sources=["graph_rule"],
                    fix_hint=f"Set 'encrypted: true' on EBS volume '{node.id}'",
                )
            )
        elif node.type == "ec2" and node.props.get("ebs_encrypted") is False:
            fid = "RULE_UNENCRYPTED_EC2_ROOT"
            findings.append(
                Finding(
                    id=fid,
                    ids=[fid, "CKV_AWS_8"],
                    severity="medium",
                    resource=node.id,
                    title=f"EC2 instance '{node.id}' has unencrypted root/attached storage",
                    source="graph_rule",
                    sources=["graph_rule"],
                    fix_hint=f"Set 'ebs_encrypted: true' on EC2 instance '{node.id}'",
                )
            )
        elif node.type == "rds" and node.props.get("storage_encrypted") is False:
            fid = "RULE_UNENCRYPTED_RDS"
            findings.append(
                Finding(
                    id=fid,
                    ids=[fid, "CKV_AWS_16"],
                    severity="medium",
                    resource=node.id,
                    title=f"RDS instance '{node.id}' does not have KMS storage encryption enabled",
                    source="graph_rule",
                    sources=["graph_rule"],
                    fix_hint=f"Set 'storage_encrypted: true' on RDS instance '{node.id}'",
                )
            )
    return findings


def rule_s3_without_versioning(graph: ArchitectureGraph) -> list[Finding]:
    """Flag S3 buckets with versioning disabled."""
    findings: list[Finding] = []
    for node in graph.architecture.nodes:
        if node.type == "s3" and node.props.get("versioning") is False:
            fid = "RULE_S3_NO_VERSIONING"
            findings.append(
                Finding(
                    id=fid,
                    ids=[fid, "CKV_AWS_21"],
                    severity="low",
                    resource=node.id,
                    title=f"S3 bucket '{node.id}' does not have object versioning enabled",
                    source="graph_rule",
                    sources=["graph_rule"],
                    fix_hint=f"Set 'versioning: true' on S3 bucket '{node.id}' to protect against accidental deletions",
                )
            )
    return findings


def rule_public_subnet_without_igw(graph: ArchitectureGraph) -> list[Finding]:
    """Flag public subnets in custom configurations that lack internet gateway connectivity."""
    findings: list[Finding] = []
    for node in graph.architecture.nodes:
        if node.type == "subnet" and node.props.get("public") is True:
            parent = graph.get_parent(node.id)
            if parent and parent.type == "vpc":
                has_explicit_route_constructs = any(
                    n.type in ("internet_gateway", "route_table")
                    for n in graph.architecture.nodes
                )
                if has_explicit_route_constructs:
                    vpc_igws = [
                        n
                        for n in graph.architecture.nodes
                        if n.type == "internet_gateway" and n.parent == parent.id
                    ]
                    if not vpc_igws:
                        fid = "RULE_PUBLIC_SUBNET_NO_IGW"
                        findings.append(
                            Finding(
                                id=fid,
                                ids=[fid],
                                severity="medium",
                                resource=node.id,
                                title=f"Public subnet '{node.id}' has no reachable Internet Gateway in VPC '{parent.id}'",
                                source="graph_rule",
                                sources=["graph_rule"],
                                fix_hint=f"Attach an internet_gateway to VPC '{parent.id}' and configure default route 0.0.0.0/0",
                            )
                        )
    return findings


ALL_RULES = [
    rule_subnet_without_vpc,
    rule_ec2_outside_subnet,
    rule_ec2_without_security_group,
    rule_open_ssh_or_rdp,
    rule_public_s3_or_public_rds,
    rule_unencrypted_storage,
    rule_s3_without_versioning,
    rule_public_subnet_without_igw,
]


def evaluate_graph_rules(architecture: Architecture) -> list[Finding]:
    """Run all deterministic graph rules against an Architecture and return findings."""
    graph = ArchitectureGraph(architecture)
    findings: list[Finding] = []
    for rule_fn in ALL_RULES:
        findings.extend(rule_fn(graph))
    return findings
