"""NetworkX graph representation and topology analysis for Cloud Copilot."""

from typing import Any

import networkx as nx

from app.models import Architecture, Node


class ArchitectureGraph:
    """NetworkX directed multi-relational graph of cloud architecture."""

    def __init__(self, architecture: Architecture) -> None:
        self.architecture = architecture
        self.nx_graph = nx.DiGraph()
        self._build_graph()

    def _build_graph(self) -> None:
        """Construct nodes and relationships in the directed graph."""
        for node in self.architecture.nodes:
            self.nx_graph.add_node(
                node.id,
                type=node.type,
                props=node.props,
                parent=node.parent,
                uses=node.uses,
            )

        # Containment edges (parent -> child)
        for node in self.architecture.nodes:
            if node.parent:
                self.nx_graph.add_edge(
                    node.parent,
                    node.id,
                    kind="containment",
                    label="contains",
                )
            for used_id in node.uses:
                self.nx_graph.add_edge(
                    node.id,
                    used_id,
                    kind="attachment",
                    label="uses",
                )

        # Explicit architecture edges
        for edge in self.architecture.edges:
            self.nx_graph.add_edge(
                edge.source,
                edge.target,
                kind=edge.kind,
                label=edge.label,
            )

    def get_node(self, node_id: str) -> Node | None:
        """Lookup node by id."""
        for n in self.architecture.nodes:
            if n.id == node_id:
                return n
        return None

    def get_children(self, parent_id: str) -> list[Node]:
        """Get all nodes whose parent is parent_id."""
        return [n for n in self.architecture.nodes if n.parent == parent_id]

    def get_parent(self, node_id: str) -> Node | None:
        """Get parent node if any."""
        node = self.get_node(node_id)
        if node and node.parent:
            return self.get_node(node.parent)
        return None

    def get_ancestors(self, node_id: str) -> list[Node]:
        """Get list of parent/grandparent nodes up the containment tree."""
        ancestors: list[Node] = []
        curr = self.get_parent(node_id)
        while curr:
            ancestors.append(curr)
            curr = self.get_parent(curr.id)
        return ancestors

    def get_used_nodes(self, node_id: str) -> list[Node]:
        """Get resources referenced in `uses` list."""
        node = self.get_node(node_id)
        if not node:
            return []
        res: list[Node] = []
        for uid in node.uses:
            target = self.get_node(uid)
            if target:
                res.append(target)
        return res

    def get_data_flow_paths(self, source_id: str, target_id: str) -> list[list[str]]:
        """Find simple directed paths between two nodes using data/network edges."""
        sub_edges = [
            (u, v)
            for u, v, d in self.nx_graph.edges(data=True)
            if d.get("kind") in ("data", "network")
        ]
        subgraph = nx.DiGraph(sub_edges)
        if source_id not in subgraph or target_id not in subgraph:
            return []
        try:
            return list(nx.all_simple_paths(subgraph, source_id, target_id, cutoff=10))
        except nx.NetworkXNoPath:
            return []

    def get_clusters(self) -> list[dict[str, Any]]:
        """Group nodes into visual clusters by VPC and Subnet hierarchy."""
        clusters: list[dict[str, Any]] = []

        # VPC clusters
        for vpc_node in self.architecture.nodes:
            if vpc_node.type == "vpc":
                subnets = [
                    n
                    for n in self.architecture.nodes
                    if n.type == "subnet" and n.parent == vpc_node.id
                ]
                direct_children = [
                    n.id
                    for n in self.architecture.nodes
                    if n.parent == vpc_node.id and n.type != "subnet"
                ]

                subnet_clusters = []
                for sub in subnets:
                    sub_members = [
                        n.id for n in self.architecture.nodes if n.parent == sub.id
                    ]
                    subnet_clusters.append(
                        {
                            "id": sub.id,
                            "type": "subnet",
                            "public": sub.props.get("public", False),
                            "cidr": sub.props.get("cidr"),
                            "members": sub_members,
                        }
                    )

                clusters.append(
                    {
                        "id": vpc_node.id,
                        "type": "vpc",
                        "cidr": vpc_node.props.get("cidr"),
                        "subnets": subnet_clusters,
                        "members": direct_children,
                    }
                )

        return clusters

    def to_visualization_dict(self) -> dict[str, Any]:
        """Produce JSON-serializable node/edge/cluster payload for frontends."""
        return {
            "nodes": [
                {
                    "id": n.id,
                    "type": n.type,
                    "parent": n.parent,
                    "uses": n.uses,
                    "props": n.props,
                }
                for n in self.architecture.nodes
            ],
            "edges": [
                {
                    "source": e.source,
                    "target": e.target,
                    "kind": e.kind,
                    "label": e.label,
                }
                for e in self.architecture.edges
            ],
            "clusters": self.get_clusters(),
        }
