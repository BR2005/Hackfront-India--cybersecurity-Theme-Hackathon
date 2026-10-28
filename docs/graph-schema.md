# GraphOps Neo4j graph schema

## Identity and labels

Every node has a stable, application-assigned `id` property. The seed uses
namespaced identifiers such as `device:ws-001` and `alert:2026-0001`.
Uniqueness constraints are created for `id` on each label:

`User`, `Device`, `IPAddress`, `Server`, `Application`, `Alert`,
`Vulnerability`, and `AttackTechnique`.

## Relationships

| Relationship | Meaning |
| --- | --- |
| `USES` | A user operates a device |
| `HAS_IP` | A device is assigned an IP address |
| `CONNECTS_TO` | A device communicates with a server |
| `RUNS` | A server hosts an application |
| `AFFECTS` | An alert identifies an affected asset |
| `USES_TECHNIQUE` | An alert is mapped to an attack technique |
| `HAS_VULNERABILITY` | An asset has a vulnerability |
| `ADMINISTERS` | A user administers a server |

Relationship records also have stable IDs, so repeated imports use `MERGE`
instead of creating duplicates. Node and relationship properties are applied
with parameter maps.

## Evidence model

`HAS_IP`, `CONNECTS_TO`, `RUNS`, path reachability, and hop counts describe
graph topology only. The blast-radius and candidate-path analyses deliberately
use only those infrastructure adjacency relationships; `USES` and
`ADMINISTERS` remain useful user context but do not create attack-path hops.
They are not proof that a device was compromised. The synthetic fixture marks
the compromised state on `Device.compromised`, while alerts and other evidence
are modeled separately.

## Example Cypher queries

The same parameterized queries are available in
`backend/app/graph_schema.py`.

### Alerts involving a device

```cypher
MATCH (device:Device {id: $device_id})<-[:AFFECTS]-(alert:Alert)
RETURN alert
ORDER BY alert.detected_at
```

### Assets connected to a selected user

```cypher
MATCH (user:User {id: $user_id})-[*1..2]-(asset)
WHERE asset:Device OR asset:IPAddress OR asset:Server OR asset:Application
RETURN DISTINCT asset
ORDER BY asset.id
```

### Candidate paths from a device to a critical server

```cypher
MATCH path = (device:Device {id: $device_id})-[*1..4]-(server:Server {id: $server_id})
WHERE server.criticality = 'critical'
RETURN path
LIMIT $limit
```

This is a candidate-path query, not a compromise determination.

### Blast radius within one, two, and three hops

```cypher
MATCH (device:Device {id: $device_id})
UNWIND [1, 2, 3] AS hops
OPTIONAL MATCH path = (device)-[:HAS_IP|CONNECTS_TO|RUNS*1..3]-(asset)
WHERE (asset:Device OR asset:IPAddress OR asset:Server OR asset:Application)
  AND asset.id <> device.id
  AND length(path) <= hops
RETURN hops, count(DISTINCT asset) AS assets
ORDER BY hops
```
