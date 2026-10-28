"""Neo4j schema and parameterized graph operations."""

NODE_LABELS = (
    "User",
    "Device",
    "IPAddress",
    "Server",
    "Application",
    "Alert",
    "Vulnerability",
    "AttackTechnique",
)

CONSTRAINT_QUERIES = tuple(
    f"CREATE CONSTRAINT {label.lower()}_id IF NOT EXISTS "
    f"FOR (node:{label}) REQUIRE node.id IS UNIQUE"
    for label in NODE_LABELS
)

NODE_UPSERT_QUERY = """
UNWIND $nodes AS item
MERGE (node:`__LABEL__` {id: item.id})
SET node += item.properties
RETURN count(node) AS count
"""

RELATIONSHIP_UPSERT_QUERY = """
UNWIND $relationships AS item
MATCH (source {id: item.source_id})
MATCH (target {id: item.target_id})
MERGE (source)-[relation:`__TYPE__` {id: item.id}]->(target)
SET relation += item.properties
RETURN count(relation) AS count
"""

# These queries are intentionally kept as application constants so they can be
# reused by API handlers and remain easy to review for parameterization.
EXAMPLE_QUERIES = {
    "alerts_for_device": """
MATCH (device:Device {id: $device_id})<-[:AFFECTS]-(alert:Alert)
RETURN alert
ORDER BY alert.detected_at
""",
    "assets_for_user": """
MATCH (user:User {id: $user_id})-[*1..2]-(asset)
WHERE asset:Device OR asset:IPAddress OR asset:Server OR asset:Application
RETURN DISTINCT asset
ORDER BY asset.id
""",
    "candidate_paths": """
MATCH path = (device:Device {id: $device_id})-[
  :HAS_IP|CONNECTS_TO|RUNS*1..4
]-(server:Server {id: $server_id})
WHERE server.criticality = 'critical'
RETURN path
LIMIT $limit
""",
    "blast_radius": """
MATCH (device:Device {id: $device_id})
UNWIND [1, 2, 3] AS hops
OPTIONAL MATCH path = (device)-[:HAS_IP|CONNECTS_TO|RUNS*1..3]-(asset)
WHERE (asset:Device OR asset:IPAddress OR asset:Server OR asset:Application)
  AND asset.id <> device.id
  AND length(path) <= hops
RETURN hops, count(DISTINCT asset) AS assets
ORDER BY hops
""",
}
