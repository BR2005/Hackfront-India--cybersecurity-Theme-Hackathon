from backend.app.analytics import build_dashboard_analytics
from backend.app.synthetic_data import synthetic_graph


def test_dashboard_analytics_is_derived_from_graph_evidence() -> None:
    nodes, relationships = synthetic_graph()

    analytics = build_dashboard_analytics(nodes, relationships)

    assert analytics["metrics"] == {
        "total_entities": 12,
        "active_alerts": 1,
        "critical_assets_at_risk": 1,
        "potential_attack_paths": 2,
        "reachable_assets_1_to_3_hops": 4,
        "high_risk_identities": 1,
    }
    assert analytics["severity_distribution"] == [
        {"severity": "Critical", "count": 0},
        {"severity": "High", "count": 1},
        {"severity": "Medium", "count": 0},
        {"severity": "Low", "count": 0},
    ]
    assert analytics["findings"][0]["classification"] == "confirmed compromise"
    assert analytics["findings"][0]["affected_asset"] == "device:ws-001"


def test_analytics_accepts_neo4j_graph_relationship_shape() -> None:
    nodes, relationships = synthetic_graph()
    neo4j_relationships = [
        {
            "id": relation["id"],
            "type": relation["type"],
            "source": relation["source_id"],
            "target": relation["target_id"],
            "properties": relation["properties"],
        }
        for relation in relationships
    ]

    analytics = build_dashboard_analytics(nodes, neo4j_relationships)

    assert analytics["metrics"]["active_alerts"] == 1
    assert analytics["attack_techniques"][0]["mitre_id"] == "T1078"
