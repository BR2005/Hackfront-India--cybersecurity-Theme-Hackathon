"""Read-only dashboard API backed by Neo4j."""

from typing import Any

from fastapi import APIRouter, HTTPException, Query
from neo4j import GraphDatabase

from .config import settings
from .analytics import build_dashboard_analytics

router = APIRouter(prefix="/api")

BLAST_RADIUS_QUERY = """
MATCH (start {id: $asset_id})
MATCH path = (start)-[:HAS_IP|CONNECTS_TO|RUNS*1..3]-(asset)
WITH start, asset, min(length(path)) AS distance, collect(path) AS all_paths
WITH start, asset, distance,
     [candidate IN all_paths WHERE length(candidate) = distance] AS shortest_paths
WHERE distance <= $hops
  AND (asset:Device OR asset:IPAddress OR asset:Server OR asset:Application)
  AND asset.id <> start.id
RETURN asset.id AS id, labels(asset)[0] AS label,
       properties(asset) AS properties, distance,
       [candidate IN shortest_paths |
         [node IN nodes(candidate) | node.id]] AS paths,
       reduce(
         relationship_ids = [],
         candidate IN shortest_paths |
           reduce(
             candidate_ids = relationship_ids,
             relationship IN relationships(candidate) |
               CASE
                 WHEN relationship.id IN candidate_ids THEN candidate_ids
                 ELSE candidate_ids + relationship.id
               END
           )
       ) AS supporting_relationships
ORDER BY distance, id
"""


def _driver():
    if not settings.neo4j_username or not settings.neo4j_password:
        raise HTTPException(status_code=503, detail="Neo4j credentials are not configured.")
    return GraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_username, settings.neo4j_password),
    )


def _records(query: str, **params: Any) -> list[dict[str, Any]]:
    driver = _driver()
    try:
        with driver.session() as session:
            return [dict(record) for record in session.run(query, **params)]
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Neo4j query failed: {exc}") from exc
    finally:
        driver.close()


@router.get("/overview")
def overview() -> dict[str, Any]:
    rows = _records(
        """
        MATCH (node)
        WITH labels(node)[0] AS label, count(node) AS count
        RETURN collect({label: label, count: count}) AS counts
        """
    )
    counts = rows[0].get("counts", []) if rows else []
    return {"mode": "neo4j", "counts": counts}


@router.get("/graph")
def graph() -> dict[str, Any]:
    nodes = _records("MATCH (node) RETURN node.id AS id, labels(node)[0] AS label, properties(node) AS properties")
    relationships = _records(
        """
        MATCH (source)-[relation]->(target)
        RETURN relation.id AS id, type(relation) AS type,
               source.id AS source, target.id AS target,
               properties(relation) AS properties
        """
    )
    return {"mode": "neo4j", "nodes": nodes, "relationships": relationships}


def _graph_records() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    graph_data = graph()
    return graph_data["nodes"], graph_data["relationships"]


@router.get("/analytics")
def analytics() -> dict[str, Any]:
    nodes, relationships = _graph_records()
    return {
        "mode": "neo4j",
        "analytics": build_dashboard_analytics(nodes, relationships),
    }


@router.get("/findings")
def findings() -> dict[str, Any]:
    nodes, relationships = _graph_records()
    return {
        "mode": "neo4j",
        "findings": build_dashboard_analytics(nodes, relationships)["findings"],
    }


@router.get("/blast-radius")
def blast_radius(asset_id: str, hops: int = Query(default=1, ge=1, le=3)) -> dict[str, Any]:
    return {
        "mode": "neo4j",
        "asset_id": asset_id,
        "hops": hops,
        "assets": _records(BLAST_RADIUS_QUERY, asset_id=asset_id, hops=hops),
    }


@router.get("/alerts")
def alerts() -> dict[str, Any]:
    return {
        "mode": "neo4j",
        "alerts": _records(
            """
            MATCH (alert:Alert)
            OPTIONAL MATCH (alert)-[:AFFECTS]->(asset)
            RETURN alert.id AS id, properties(alert) AS properties,
                   collect(asset.id) AS affected_assets
            ORDER BY properties.detected_at DESC
            """
        ),
    }


@router.get("/assets")
def assets() -> dict[str, Any]:
    return {
        "mode": "neo4j",
        "assets": _records(
            """
            MATCH (asset)
            WHERE asset:Device OR asset:IPAddress OR asset:Server OR asset:Application
            RETURN asset.id AS id, labels(asset)[0] AS label, properties(asset) AS properties
            ORDER BY id
            """
        ),
    }


@router.get("/sources")
def sources() -> dict[str, Any]:
    _records("RETURN 1 AS connected")
    return {"mode": "neo4j", "sources": [{"name": "Neo4j", "status": "connected"}]}
