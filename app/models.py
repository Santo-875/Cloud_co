"""Domain models and schemas for Cloud Copilot."""

import re
from ipaddress import IPv4Network
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

ResourceType = Literal[
    "vpc",
    "subnet",
    "security_group",
    "ec2",
    "ebs",
    "s3",
    "cloudwatch",
    "sns",
    "iam_role",
    "rds",
    "internet_gateway",
    "route_table",
]

NODE_ID_REGEX = re.compile(r"^[a-z][a-z0-9_]{0,40}$")
INSTANCE_TYPE_REGEX = re.compile(r"^[a-z][0-9][a-z]?\.[a-z0-9]+$")


class StrictPropsBase(BaseModel):
    """Base model forbidding undeclared property keys."""

    model_config = ConfigDict(extra="forbid")


class VpcProps(StrictPropsBase):
    cidr: str

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, v: str) -> str:
        try:
            net = IPv4Network(v, strict=False)
            if net.prefixlen < 16 or net.prefixlen > 28:
                raise ValueError("VPC CIDR prefix must be between /16 and /28")
        except Exception as err:
            raise ValueError(f"Invalid IPv4 CIDR for VPC: {err}") from err
        return v


class SubnetProps(StrictPropsBase):
    cidr: str
    public: bool = False
    az: str | None = None

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, v: str) -> str:
        try:
            IPv4Network(v, strict=False)
        except Exception as err:
            raise ValueError(f"Invalid IPv4 CIDR for Subnet: {err}") from err
        return v


class IngressRule(StrictPropsBase):
    port: int = Field(ge=0, le=65535)
    to_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: Literal["tcp", "udp", "icmp", "all", "-1"] = "tcp"
    cidr: str = "0.0.0.0/0"

    @field_validator("protocol", mode="before")
    @classmethod
    def convert_protocol(cls, v: Any) -> Any:
        if v == -1:
            return "-1"
        return v

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, v: str) -> str:
        try:
            IPv4Network(v, strict=False)
        except Exception as err:
            raise ValueError(f"Invalid IPv4 CIDR for ingress rule: {err}") from err
        return v


class EgressRule(StrictPropsBase):
    port: int | None = Field(default=0, ge=0, le=65535)
    to_port: int | None = Field(default=0, ge=0, le=65535)
    protocol: Literal["tcp", "udp", "icmp", "all", "-1"] = "-1"
    cidr: str = "0.0.0.0/0"

    @field_validator("protocol", mode="before")
    @classmethod
    def convert_protocol(cls, v: Any) -> Any:
        if v == -1:
            return "-1"
        return v

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, v: str) -> str:
        try:
            IPv4Network(v, strict=False)
        except Exception as err:
            raise ValueError(f"Invalid IPv4 CIDR for egress rule: {err}") from err
        return v


class SecurityGroupProps(StrictPropsBase):
    description: str | None = None
    ingress: list[IngressRule] = Field(default_factory=list)
    egress: list[EgressRule] = Field(default_factory=list)


class Ec2Props(StrictPropsBase):
    instance_type: str = "t3.micro"
    ebs_encrypted: bool = True
    key_name: str | None = None
    associate_public_ip_address: bool | None = None

    @field_validator("instance_type")
    @classmethod
    def validate_instance_type(cls, v: str) -> str:
        if not INSTANCE_TYPE_REGEX.match(v):
            raise ValueError(
                f"Invalid EC2 instance type '{v}'. Must match format like 't3.micro' or 'm5.large'"
            )
        return v


class S3Props(StrictPropsBase):
    versioning: bool = True
    public: bool = False
    encryption: bool = True


class EbsProps(StrictPropsBase):
    size_gb: int = Field(default=20, ge=1, le=16384)
    encrypted: bool = True
    volume_type: Literal["gp2", "gp3", "io1", "io2", "standard"] = "gp3"


class RdsProps(StrictPropsBase):
    engine: Literal["postgres", "mysql"] = "postgres"
    instance_class: str = "db.t3.micro"
    allocated_storage: int = Field(default=20, ge=20, le=65536)
    publicly_accessible: bool = False
    storage_encrypted: bool = True


class CloudwatchProps(StrictPropsBase):
    retention_days: int = Field(default=30, ge=1, le=3650)


class SnsProps(StrictPropsBase):
    display_name: str | None = None


class IamRoleProps(StrictPropsBase):
    assume_role_service: str = "ec2.amazonaws.com"
    managed_policy_arns: list[str] = Field(default_factory=list)


class InternetGatewayProps(StrictPropsBase):
    tags: dict[str, str] = Field(default_factory=dict)


class RouteTableProps(StrictPropsBase):
    routes: list[dict[str, str]] = Field(default_factory=list)


PROPS_MODEL_MAP: dict[ResourceType, type[StrictPropsBase]] = {
    "vpc": VpcProps,
    "subnet": SubnetProps,
    "security_group": SecurityGroupProps,
    "ec2": Ec2Props,
    "ebs": EbsProps,
    "s3": S3Props,
    "cloudwatch": CloudwatchProps,
    "sns": SnsProps,
    "iam_role": IamRoleProps,
    "rds": RdsProps,
    "internet_gateway": InternetGatewayProps,
    "route_table": RouteTableProps,
}


class Node(BaseModel):
    """Architecture resource node."""

    id: str
    type: ResourceType
    props: dict[str, Any] = Field(default_factory=dict)
    parent: str | None = None  # containment: e.g. subnet in vpc
    uses: list[str] = Field(
        default_factory=list
    )  # attachment: e.g. ec2 uses security group

    @field_validator("id")
    @classmethod
    def validate_id_format(cls, v: str) -> str:
        if not NODE_ID_REGEX.match(v):
            raise ValueError(
                f"Node ID '{v}' is invalid. Must match regex '^[a-z][a-z0-9_]{{0,40}}$'"
            )
        return v

    def validate_props(self) -> StrictPropsBase:
        """Validate and return typed props for this node type."""
        model_cls = PROPS_MODEL_MAP.get(self.type)
        if model_cls is None:
            raise ValueError(f"Unsupported resource type '{self.type}'")
        return model_cls.model_validate(self.props)


class Edge(BaseModel):
    """Architecture connection edge."""

    source: str
    target: str
    kind: Literal["data", "network", "iam", "monitoring"]
    label: str | None = None


class Architecture(BaseModel):
    """Complete verified architecture definition."""

    name: str
    region: str = Field(..., pattern=r"^[a-z]{2}(-[a-z]+)+-\d$")
    nodes: list[Node]
    edges: list[Edge] = Field(default_factory=list)


class Finding(BaseModel):
    """Normalized security or configuration finding."""

    id: str  # Canonical or primary check id for display
    ids: list[str] = Field(default_factory=list)  # All merged check ids
    severity: Literal["low", "medium", "high", "critical"]
    resource: str  # node id
    title: str
    source: Literal["checkov", "trivy", "validate", "graph_rule"]
    sources: list[Literal["checkov", "trivy", "validate", "graph_rule"]] = Field(
        default_factory=list
    )
    fix_hint: str | None = None


class PatchOperation(BaseModel):
    """A granular patch operation modifying an architecture node."""

    op: Literal["add_node", "remove_node", "change_props"]
    target_node_id: str
    node: Node | None = None
    props_patch: dict[str, Any] = Field(default_factory=dict)


class ArchitecturePatch(BaseModel):
    """Set of patch operations to remediate findings."""

    patch_id: str
    architecture_id: str
    operations: list[PatchOperation] = Field(default_factory=list)


class DiagnosticBlocker(BaseModel):
    """A ranked blocker preventing reachability between two components."""

    rank: int
    category: Literal[
        "security_group_ingress",
        "security_group_egress",
        "subnet_routing",
        "vpc_boundary",
        "missing_connection",
        "unknown_resource",
    ]
    summary: str
    evidence: dict[str, Any] = Field(default_factory=dict)


class DiagnoseResponse(BaseModel):
    """Deterministic reachability diagnosis and ranked blockers."""

    reachable: bool
    source: str
    target: str
    blockers: list[DiagnosticBlocker] = Field(default_factory=list)
    graph_evidence: dict[str, Any] = Field(default_factory=dict)
    explanation: str
