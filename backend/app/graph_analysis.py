"""Evidence-aware graph traversal helpers used by tests and demo analysis."""

from collections import deque
from typing import TypedDict

from .synthetic_data import GraphRecord, RelationshipRecord

ASSET_LABELS = frozenset({"Device", "IPAddress", "Server", "Application"})
ATTACK_PATH_RELATIONSHIP_TYPES = frozenset(
    {"HAS_IP", "CONNECTS_TO", "RUNS"}
)


class ReachableAsset(TypedDict):
    id: str
    label: str
    properties: dict[str, object]
    distance: int
    paths: list[list[str]]
    relationships: list[str]


def analyze_blast_radius(
    nodes: list[GraphRecord],
    relationships: list[RelationshipRecord],
    start_id: str,
    hop_limit: int,
) -> list[ReachableAsset]:
    """Return unique asset nodes with shortest distances and supporting paths."""
    if hop_limit not in (1, 2, 3):
        raise ValueError("hop_limit must be 1, 2, or 3")
    node_by_id = {node["id"]: node for node in nodes}
    if start_id not in node_by_id:
        return []
    adjacency: dict[str, list[tuple[str, str, str]]] = {}
    for relationship in relationships:
        if relationship["type"] not in ATTACK_PATH_RELATIONSHIP_TYPES:
            continue
        source = relationship["source_id"]
        target = relationship["target_id"]
        adjacency.setdefault(source, []).append((target, relationship["id"], relationship["type"]))
        adjacency.setdefault(target, []).append((source, relationship["id"], relationship["type"]))

    distances = {start_id: 0}
    paths: dict[str, list[list[str]]] = {start_id: [[start_id]]}
    supporting: dict[str, set[str]] = {start_id: set()}
    queue = deque([start_id])
    while queue:
        current = queue.popleft()
        if distances[current] >= hop_limit:
            continue
        for neighbor, relationship_id, _ in adjacency.get(current, []):
            candidate_distance = distances[current] + 1
            candidate_paths = [path + [neighbor] for path in paths[current]]
            if neighbor not in distances:
                distances[neighbor] = candidate_distance
                paths[neighbor] = candidate_paths
                supporting[neighbor] = set().union(
                    *(supporting[current] | {relationship_id} for _ in candidate_paths)
                )
                queue.append(neighbor)
            elif candidate_distance == distances[neighbor]:
                for candidate_path in candidate_paths:
                    if candidate_path not in paths[neighbor]:
                        paths[neighbor].append(candidate_path)
                supporting[neighbor].add(relationship_id)

    result: list[ReachableAsset] = []
    for asset_id, distance in distances.items():
        if asset_id == start_id or distance > hop_limit:
            continue
        node = node_by_id.get(asset_id)
        if node is None:
            continue
        if node["label"] not in ASSET_LABELS:
            continue
        result.append(
            {
                "id": asset_id,
                "label": node["label"],
                "properties": node["properties"],
                "distance": distance,
                "paths": paths[asset_id],
                "relationships": sorted(supporting[asset_id]),
            }
        )
    return sorted(result, key=lambda asset: (asset["distance"], asset["id"]))
