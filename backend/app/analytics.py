"""Explainable dashboard analytics derived from Neo4j graph records."""

from collections import Counter, defaultdict
from typing import Any

from .graph_analysis import ASSET_LABELS, analyze_blast_radius
from .synthetic_data import GraphRecord, RelationshipRecord

SEVERITIES = ("critical", "high", "medium", "low")
ASSET_GROUPS = {
    "User": "Users",
    "Device": "Devices",
    "Server": "Servers",
    "Application": "Applications",
    "IPAddress": "IP addresses",
    "Vulnerability": "Vulnerabilities",
}


def _severity(value: object) -> str:
    normalized = str(value or "low").lower()
    return normalized if normalized in SEVERITIES else "low"


def _score(severity: str, criticality: object, confidence: int, exposure: int) -> int:
    severity_points = {"critical": 40, "high": 30, "medium": 20, "low": 10}
    criticality_points = {"critical": 30, "high": 20, "medium": 10, "low": 5}
    return min(
        100,
        severity_points[severity]
        + criticality_points.get(str(criticality or "low").lower(), 5)
        + min(confidence, 10)
        + min(exposure * 2, 20),
    )


def _source(relation: RelationshipRecord | dict[str, Any]) -> str:
    return str(relation.get("source_id", relation.get("source", "")))


def _target(relation: RelationshipRecord | dict[str, Any]) -> str:
    return str(relation.get("target_id", relation.get("target", "")))


def build_dashboard_analytics(
    nodes: list[GraphRecord],
    relationships: list[RelationshipRecord],
) -> dict[str, Any]:
    node_by_id = {node["id"]: node for node in nodes}
    normalized_relationships: list[RelationshipRecord] = [
        {
            "id": str(relation["id"]),
            "type": str(relation["type"]),
            "source_id": _source(relation),
            "target_id": _target(relation),
            "properties": relation.get("properties", {}),
        }
        for relation in relationships
    ]
    alerts = [node for node in nodes if node["label"] == "Alert"]
    asset_nodes = [node for node in nodes if node["label"] in ASSET_LABELS]
    affected_by_alert: dict[str, list[str]] = defaultdict(list)
    for relation in relationships:
        if relation["type"] == "AFFECTS":
            affected_by_alert[_source(relation)].append(_target(relation))

    severity_counts = Counter(
        _severity(alert["properties"].get("severity")) for alert in alerts
    )
    trend_counts = Counter(
        str(alert["properties"].get("detected_at", ""))[:10] or "unknown"
        for alert in alerts
    )
    asset_counts = Counter(ASSET_GROUPS[node["label"]] for node in nodes if node["label"] in ASSET_GROUPS)
    risk_counts = Counter(
        str(node["properties"].get("criticality", "unclassified")).lower()
        for node in asset_nodes
    )
    techniques = [
        {
            "id": node["id"],
            "name": node["properties"].get("name", node["id"]),
            "mitre_id": node["properties"].get("mitre_id"),
            "related_alerts": [
                alert["id"]
                for alert in alerts
                if node["id"] in {
                    _target(relation)
                    for relation in relationships
                    if _source(relation) == alert["id"]
                    and relation["type"] == "USES_TECHNIQUE"
                }
            ],
        }
        for node in nodes
        if node["label"] == "AttackTechnique"
    ]

    findings: list[dict[str, Any]] = []
    for alert in alerts:
        severity = _severity(alert["properties"].get("severity"))
        affected_assets = [
            node_by_id[asset_id]
            for asset_id in affected_by_alert.get(alert["id"], [])
            if asset_id in node_by_id
        ]
        if not affected_assets:
            findings.append(
                {
                    "id": alert["id"],
                    "title": f"{severity.title()} alert requires triage",
                    "severity": severity,
                    "affected_asset": None,
                    "evidence_summary": "Alert has no linked affected asset.",
                    "related_entities": [],
                    "potential_impact": "Impact cannot be assessed until the alert is correlated.",
                    "next_step": "Validate alert source and correlate additional evidence.",
                    "status": "needs-review",
                    "classification": "observed suspicious activity",
                    "risk_score": _score(severity, "low", 1, 0),
                }
            )
            continue
        for asset in affected_assets:
            exposure = sum(
                1
                for relation in relationships
                if _source(relation) == asset["id"] or _target(relation) == asset["id"]
            )
            compromised = asset["properties"].get("compromised") is True
            classification = "confirmed compromise" if compromised else "observed suspicious activity"
            findings.append(
                {
                    "id": f"{alert['id']}:{asset['id']}",
                    "title": f"{severity.title()} alert on {asset['properties'].get('hostname', asset['id'])}",
                    "severity": severity,
                    "affected_asset": asset["id"],
                    "evidence_summary": f"Alert {alert['id']} is linked to {asset['id']} by AFFECTS.",
                    "related_entities": affected_by_alert.get(alert["id"], []),
                    "potential_impact": "Confirmed device state is compromised." if compromised else "Reachability indicates exposure, not confirmed compromise.",
                    "next_step": "Review alert evidence and neighboring relationships before containment.",
                    "status": "confirmed" if compromised else "investigate",
                    "classification": classification,
                    "risk_score": _score(
                        severity,
                        asset["properties"].get("criticality"),
                        8 if compromised else 5,
                        exposure,
                    ),
                }
            )

    compromised_assets = [
        node for node in asset_nodes if node["properties"].get("compromised") is True
    ]
    reachable_ids: set[str] = set()
    potential_paths = 0
    for asset in compromised_assets:
        blast = analyze_blast_radius(
            nodes,
            normalized_relationships,
            asset["id"],
            3,
        )
        reachable_ids.update(item["id"] for item in blast)
        potential_paths += sum(len(item["paths"]) for item in blast if item["label"] == "Server")

    return {
        "metrics": {
            "total_entities": len(nodes),
            "active_alerts": len(alerts),
            "critical_assets_at_risk": sum(
                1
                for node in asset_nodes
                if str(node["properties"].get("criticality", "")).lower() == "critical"
            ),
            "potential_attack_paths": potential_paths,
            "reachable_assets_1_to_3_hops": len(reachable_ids),
            "high_risk_identities": sum(
                1
                for node in nodes
                if node["label"] == "User"
                and str(node["properties"].get("role", "")).lower() in {"admin", "service"}
            ),
        },
        "severity_distribution": [
            {"severity": severity.title(), "count": severity_counts[severity]}
            for severity in SEVERITIES
        ],
        "alert_trends": [
            {"date": date, "count": trend_counts[date]}
            for date in sorted(trend_counts)
        ],
        "asset_distribution": [
            {"type": group, "count": asset_counts[group]}
            for group in ASSET_GROUPS.values()
        ],
        "risk_distribution": [
            {"risk": risk.title(), "count": risk_counts[risk]}
            for risk in ("critical", "high", "medium", "low", "unclassified")
            if risk_counts[risk]
        ],
        "attack_techniques": techniques,
        "findings": sorted(
            findings,
            key=lambda finding: (-finding["risk_score"], finding["id"]),
        ),
        "scoring": {
            "formula": "severity (10-40) + criticality (5-30) + evidence confidence (0-10) + exposure (0-20), capped at 100",
            "note": "Reachability alone is never treated as confirmed compromise.",
        },
    }
