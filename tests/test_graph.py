"""Tests for app/graph.py."""

from app.graph import ArchitectureGraph
from app.models import Architecture, Edge, Node


def test_graph_hierarchy_and_clusters() -> None:
    arch = Architecture(
        name="clustered_arch",
        region="us-east-1",
        nodes=[
            Node(id="vpc_1", type="vpc", props={"cidr": "10.0.0.0/16"}),
            Node(
                id="sub_pub",
                type="subnet",
                parent="vpc_1",
                props={"cidr": "10.0.1.0/24", "public": True},
            ),
            Node(
                id="ec2_1",
                type="ec2",
                parent="sub_pub",
                props={"instance_type": "t3.micro"},
            ),
            Node(id="s3_1", type="s3", props={"public": False}),
        ],
        edges=[
            Edge(source="ec2_1", target="s3_1", kind="data", label="logs"),
        ],
    )
    graph = ArchitectureGraph(arch)

    # Children check
    vpc_children = graph.get_children("vpc_1")
    assert len(vpc_children) == 1
    assert vpc_children[0].id == "sub_pub"

    sub_children = graph.get_children("sub_pub")
    assert len(sub_children) == 1
    assert sub_children[0].id == "ec2_1"

    # Parent & Ancestors check
    assert graph.get_parent("ec2_1").id == "sub_pub"
    ancestors = graph.get_ancestors("ec2_1")
    assert [a.id for a in ancestors] == ["sub_pub", "vpc_1"]

    # Data flow paths
    paths = graph.get_data_flow_paths("ec2_1", "s3_1")
    assert paths == [["ec2_1", "s3_1"]]

    # Clusters payload
    clusters = graph.get_clusters()
    assert len(clusters) == 1
    assert clusters[0]["id"] == "vpc_1"
    assert len(clusters[0]["subnets"]) == 1
    assert clusters[0]["subnets"][0]["id"] == "sub_pub"
    assert clusters[0]["subnets"][0]["members"] == ["ec2_1"]

    # Visualization serialization
    vis_data = graph.to_visualization_dict()
    assert len(vis_data["nodes"]) == 4
    assert len(vis_data["edges"]) == 1
    assert len(vis_data["clusters"]) == 1
