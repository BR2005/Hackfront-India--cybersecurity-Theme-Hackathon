"""Neo4j driver-backed graph repository."""

from collections.abc import Iterable
from typing import Any

from neo4j import Driver

from .graph_schema import CONSTRAINT_QUERIES, NODE_UPSERT_QUERY, RELATIONSHIP_UPSERT_QUERY
from .synthetic_data import GraphRecord, RelationshipRecord


class GraphRepository:
    def __init__(self, driver: Driver) -> None:
        self.driver = driver

    def initialize_schema(self) -> None:
        with self.driver.session() as session:
            for query in CONSTRAINT_QUERIES:
                session.run(query)

    def upsert_nodes(self, nodes: Iterable[GraphRecord]) -> int:
        grouped: dict[str, list[dict[str, Any]]] = {}
        seen_ids: set[str] = set()
        for node in nodes:
            if node["id"] in seen_ids:
                continue
            seen_ids.add(node["id"])
            grouped.setdefault(node["label"], []).append(
                {"id": node["id"], "properties": node["properties"]}
            )
        total = 0
        with self.driver.session() as session:
            for label, records in grouped.items():
                result = session.run(NODE_UPSERT_QUERY.replace("__LABEL__", label), nodes=records)
                total += result.single()["count"]
        return total

    def upsert_relationships(self, relationships: Iterable[RelationshipRecord]) -> int:
        grouped: dict[str, list[dict[str, Any]]] = {}
        seen_ids: set[str] = set()
        for relationship in relationships:
            if relationship["id"] in seen_ids:
                continue
            seen_ids.add(relationship["id"])
            grouped.setdefault(relationship["type"], []).append(relationship)
        total = 0
        with self.driver.session() as session:
            for relationship_type, records in grouped.items():
                result = session.run(
                    RELATIONSHIP_UPSERT_QUERY.replace("__TYPE__", relationship_type),
                    relationships=records,
                )
                total += result.single()["count"]
        return total

    def seed(self, nodes: Iterable[GraphRecord], relationships: Iterable[RelationshipRecord]) -> tuple[int, int]:
        self.initialize_schema()
        return self.upsert_nodes(nodes), self.upsert_relationships(relationships)
