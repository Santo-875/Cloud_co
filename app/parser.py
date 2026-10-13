"""Parser and validator for untrusted architecture YAML input."""

from typing import Any

import yaml
from pydantic import ValidationError

from app.models import Architecture, Edge, Node

MAX_INPUT_BYTES = 100 * 1024  # 100 KB
MAX_NODES = 200


class ParserError(Exception):
    """Raised when architecture YAML fails syntax, safety, or structural limits."""

    def __init__(self, message: str, details: list[str] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or []

    def __str__(self) -> str:
        if self.details:
            return f"{self.message}: {'; '.join(self.details)}"
        return self.message


def _check_cycles(nodes: list[Node]) -> None:
    """Verify there are no circular dependencies in containment or attachment hierarchies."""
    parent_map = {n.id: n.parent for n in nodes if n.parent is not None}
    for start_id in parent_map:
        visited: set[str] = set()
        curr: str | None = start_id
        while curr is not None:
            if curr in visited:
                raise ParserError(f"Cycle detected in parent containment: '{curr}'")
            visited.add(curr)
            curr = parent_map.get(curr)

    uses_map = {n.id: n.uses for n in nodes}
    global_visited: set[str] = set()

    def dfs(curr_id: str, stack: set[str], visited_set: set[str]) -> None:
        if curr_id in stack:
            raise ParserError(f"Cycle detected in 'uses' attachment: '{curr_id}'")
        if curr_id in visited_set:
            return
        stack.add(curr_id)
        visited_set.add(curr_id)
        for neighbor in uses_map.get(curr_id, []):
            dfs(neighbor, stack, visited_set)
        stack.remove(curr_id)

    for start_id in uses_map:
        if start_id not in global_visited:
            dfs(start_id, set(), global_visited)


def parse_architecture(raw_input: str | bytes | dict[str, Any]) -> Architecture:
    """Parse and strictly validate raw architecture definition.

    Enforces:
    - 100 KB limit for raw text / bytes.
    - Max 200 nodes.
    - safe_load only.
    - Node id regex ^[a-z][a-z0-9_]{0,40}$.
    - Typed props schema per resource type with extra="forbid".
    - Referential integrity on parent, uses, source, target.
    - Cycle detection on parent containment and uses attachment.
    """
    if isinstance(raw_input, (str, bytes)):
        raw_bytes = (
            raw_input.encode("utf-8") if isinstance(raw_input, str) else raw_input
        )
        if len(raw_bytes) > MAX_INPUT_BYTES:
            raise ParserError(
                f"Input exceeds size cap of {MAX_INPUT_BYTES} bytes (received {len(raw_bytes)})"
            )
        try:
            payload = yaml.safe_load(raw_bytes)
        except yaml.YAMLError as exc:
            raise ParserError(f"Invalid YAML syntax: {exc}") from exc
    elif isinstance(raw_input, dict):
        payload = raw_input
    else:
        raise ParserError(f"Unsupported payload type: {type(raw_input).__name__}")

    if not isinstance(payload, dict):
        raise ParserError("Architecture root must be a YAML mapping / JSON dictionary")

    name = payload.get("name")
    region = payload.get("region")
    if not isinstance(name, str) or not name.strip():
        raise ParserError("Architecture requires a non-empty string 'name'")
    if not isinstance(region, str) or not region.strip():
        raise ParserError("Architecture requires a non-empty string 'region'")

    raw_resources = payload.get("resources")
    raw_nodes = payload.get("nodes")
    if raw_resources is None and raw_nodes is None:
        raise ParserError("Architecture must define 'resources' or 'nodes'")

    resources_list = raw_resources if raw_resources is not None else raw_nodes
    if not isinstance(resources_list, list):
        raise ParserError("'resources' / 'nodes' must be a list")

    if len(resources_list) > MAX_NODES:
        raise ParserError(
            f"Node count exceeds limit of {MAX_NODES} (found {len(resources_list)})"
        )

    raw_connections = payload.get("connections")
    raw_edges = payload.get("edges")
    connections_list = (
        raw_connections
        if raw_connections is not None
        else (raw_edges if raw_edges is not None else [])
    )
    if not isinstance(connections_list, list):
        raise ParserError("'connections' / 'edges' must be a list")

    nodes: list[Node] = []
    seen_ids: set[str] = set()

    for item in resources_list:
        if not isinstance(item, dict):
            raise ParserError("Every resource item must be a dictionary")

        node_id = item.get("id")
        res_type = item.get("type")
        parent = item.get("in", item.get("parent"))
        uses = item.get("uses", [])
        props = item.get("props", {})

        if not isinstance(props, dict):
            raise ParserError(
                f"Properties for node '{node_id}' must be a dictionary/mapping"
            )

        if node_id in seen_ids:
            raise ParserError(f"Duplicate resource id: '{node_id}'")
        seen_ids.add(node_id)

        try:
            node = Node(
                id=node_id,
                type=res_type,  # type: ignore[arg-type]
                props=props,
                parent=parent,
                uses=uses if isinstance(uses, list) else [uses],
            )
        except ValidationError as err:
            err_msgs = [f"{e['loc']}: {e['msg']}" for e in err.errors()]
            raise ParserError(
                f"Validation failed for node '{node_id}'", details=err_msgs
            ) from err

        # Validate typed props
        try:
            node.validate_props()
        except ValidationError as err:
            err_msgs = [f"{e['loc']}: {e['msg']}" for e in err.errors()]
            raise ParserError(
                f"Invalid properties for node '{node_id}' of type '{node.type}'",
                details=err_msgs,
            ) from err
        except ValueError as err:
            raise ParserError(
                f"Invalid properties for node '{node_id}': {err}"
            ) from err

        nodes.append(node)

    # Referential integrity on nodes
    for node in nodes:
        if node.parent is not None and node.parent not in seen_ids:
            raise ParserError(
                f"Resource '{node.id}' references non-existent parent '{node.parent}'"
            )
        for used in node.uses:
            if used not in seen_ids:
                raise ParserError(
                    f"Resource '{node.id}' references non-existent attachment in 'uses': '{used}'"
                )

    edges: list[Edge] = []
    for conn in connections_list:
        if not isinstance(conn, dict):
            raise ParserError("Every connection item must be a dictionary")

        src = conn.get("from", conn.get("source"))
        tgt = conn.get("to", conn.get("target"))
        kind = conn.get("kind")
        label = conn.get("label")

        if src not in seen_ids:
            raise ParserError(
                f"Connection references non-existent source node: '{src}'"
            )
        if tgt not in seen_ids:
            raise ParserError(
                f"Connection references non-existent target node: '{tgt}'"
            )

        try:
            edge = Edge(
                source=src,
                target=tgt,
                kind=kind,  # type: ignore[arg-type]
                label=label,
            )
        except ValidationError as err:
            err_msgs = [f"{e['loc']}: {e['msg']}" for e in err.errors()]
            raise ParserError("Validation failed for connection", details=err_msgs)

        edges.append(edge)

    # Cycle check
    _check_cycles(nodes)

    return Architecture(
        name=name.strip(),
        region=region.strip(),
        nodes=nodes,
        edges=edges,
    )
