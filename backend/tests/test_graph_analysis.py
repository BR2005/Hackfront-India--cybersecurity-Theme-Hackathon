from backend.app.graph_analysis import analyze_blast_radius
from backend.app.synthetic_data import synthetic_graph


def test_expected_blast_radius_distances_and_attack_route() -> None:
    nodes, relationships = synthetic_graph()

    one_hop = analyze_blast_radius(nodes, relationships, "device:ws-001", 1)
    two_hop = analyze_blast_radius(nodes, relationships, "device:ws-001", 2)
    three_hop = analyze_blast_radius(nodes, relationships, "device:ws-001", 3)

    assert [(item["id"], item["distance"]) for item in one_hop] == [
        ("ip:10.0.1.10", 1),
        ("server:ad-01", 1),
        ("server:files-01", 1),
    ]
    assert [(item["id"], item["distance"]) for item in two_hop] == [
        ("ip:10.0.1.10", 1),
        ("server:ad-01", 1),
        ("server:files-01", 1),
        ("app:portal", 2),
    ]
    assert [(item["id"], item["distance"]) for item in three_hop] == [
        ("ip:10.0.1.10", 1),
        ("server:ad-01", 1),
        ("server:files-01", 1),
        ("app:portal", 2),
    ]

    portal = next(item for item in two_hop if item["id"] == "app:portal")
    assert portal["paths"] == [["device:ws-001", "server:files-01", "app:portal"]]


def test_cycles_are_deduplicated_and_disconnected_assets_are_excluded() -> None:
    nodes, relationships = synthetic_graph()
    nodes.extend(
        [
            {"id": "server:isolated", "label": "Server", "properties": {"hostname": "ISOLATED"}},
        ]
    )
    relationships.extend(
        [
            {
                "id": "rel:portal-back-to-ws",
                "type": "CONNECTS_TO",
                "source_id": "app:portal",
                "target_id": "device:ws-001",
                "properties": {},
            },
            {
                "id": "rel:unsupported-alert",
                "type": "AFFECTS",
                "source_id": "alert:2026-0001",
                "target_id": "server:isolated",
                "properties": {},
            },
        ]
    )

    result = analyze_blast_radius(nodes, relationships, "device:ws-001", 3)
    ids = [item["id"] for item in result]

    assert len(ids) == len(set(ids))
    assert "server:isolated" not in ids
    assert "alert:2026-0001" not in ids
    assert "vuln:cve-2025-0001" not in ids
    assert "technique:T1078" not in ids


def test_duplicate_shortest_paths_are_returned_once_with_all_relationships() -> None:
    nodes, relationships = synthetic_graph()
    relationships.extend(
        [
            {
                "id": "rel:ad-to-portal",
                "type": "RUNS",
                "source_id": "server:ad-01",
                "target_id": "app:portal",
                "properties": {},
            },
        ]
    )

    result = analyze_blast_radius(nodes, relationships, "device:ws-001", 2)
    portal = next(item for item in result if item["id"] == "app:portal")

    assert portal["distance"] == 2
    assert portal["paths"] == [
        ["device:ws-001", "server:ad-01", "app:portal"],
        ["device:ws-001", "server:files-01", "app:portal"],
    ]
    assert portal["relationships"] == [
        "rel:ad-to-portal",
        "rel:files-runs-portal",
        "rel:ws1-connects-ad",
    ]


def test_asset_with_no_neighbors_returns_no_assets() -> None:
    nodes, relationships = synthetic_graph()
    nodes.append({"id": "device:isolated", "label": "Device", "properties": {}})

    assert analyze_blast_radius(nodes, relationships, "device:isolated", 1) == []


def test_unsupported_relationships_do_not_create_attack_paths() -> None:
    nodes, relationships = synthetic_graph()
    relationships.append(
        {
            "id": "rel:alert-to-ad",
            "type": "USES_TECHNIQUE",
            "source_id": "alert:2026-0001",
            "target_id": "server:ad-01",
            "properties": {},
        }
    )

    result = analyze_blast_radius(nodes, relationships, "alert:2026-0001", 3)

    assert result == []


def test_reachability_and_benign_events_are_not_compromise_findings() -> None:
    nodes, relationships = synthetic_graph()

    result = analyze_blast_radius(nodes, relationships, "device:ws-002", 3)

    assert result
    assert nodes[3]["properties"]["compromised"] is False
    assert all("confirmed_compromise" not in item for item in result)
