"""Seed Neo4j with the deterministic GraphOps fixture."""

from neo4j import GraphDatabase

from backend.app.config import settings
from backend.app.neo4j_repository import GraphRepository
from backend.app.synthetic_data import synthetic_graph


def main() -> None:
    if not settings.neo4j_username or not settings.neo4j_password:
        raise RuntimeError("Set NEO4J_USERNAME and NEO4J_PASSWORD before seeding.")
    nodes, relationships = synthetic_graph()
    driver = GraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_username, settings.neo4j_password),
    )
    try:
        node_count, relationship_count = GraphRepository(driver).seed(nodes, relationships)
        print(f"Seeded {node_count} nodes and {relationship_count} relationships.")
    finally:
        driver.close()


if __name__ == "__main__":
    main()
