"""Deterministic, non-production cybersecurity graph fixtures."""

from typing import TypedDict


class GraphRecord(TypedDict):
    id: str
    label: str
    properties: dict[str, object]


class RelationshipRecord(TypedDict):
    id: str
    type: str
    source_id: str
    target_id: str
    properties: dict[str, object]


def synthetic_graph() -> tuple[list[GraphRecord], list[RelationshipRecord]]:
    nodes: list[GraphRecord] = [
        {"id": "user:alice", "label": "User", "properties": {"name": "Alice Chen", "role": "analyst"}},
        {"id": "user:svc-backup", "label": "User", "properties": {"name": "svc-backup", "role": "service"}},
        {"id": "device:ws-001", "label": "Device", "properties": {"hostname": "WS-001", "compromised": True}},
        {"id": "device:ws-002", "label": "Device", "properties": {"hostname": "WS-002", "compromised": False}},
        {"id": "ip:10.0.1.10", "label": "IPAddress", "properties": {"address": "10.0.1.10"}},
        {"id": "ip:10.0.1.20", "label": "IPAddress", "properties": {"address": "10.0.1.20"}},
        {"id": "server:ad-01", "label": "Server", "properties": {"hostname": "AD-01", "criticality": "critical"}},
        {"id": "server:files-01", "label": "Server", "properties": {"hostname": "FILES-01", "criticality": "high"}},
        {"id": "app:portal", "label": "Application", "properties": {"name": "Employee Portal"}},
        {"id": "alert:2026-0001", "label": "Alert", "properties": {"severity": "high", "detected_at": "2026-01-15T08:00:00Z"}},
        {"id": "vuln:cve-2025-0001", "label": "Vulnerability", "properties": {"cve": "CVE-2025-0001", "severity": "high"}},
        {"id": "technique:T1078", "label": "AttackTechnique", "properties": {"name": "Valid Accounts", "mitre_id": "T1078"}},
    ]
    relationships: list[RelationshipRecord] = [
        {"id": "rel:alice-uses-ws1", "type": "USES", "source_id": "user:alice", "target_id": "device:ws-001", "properties": {}},
        {"id": "rel:alice-uses-ws2", "type": "USES", "source_id": "user:alice", "target_id": "device:ws-002", "properties": {}},
        {"id": "rel:ws1-has-ip", "type": "HAS_IP", "source_id": "device:ws-001", "target_id": "ip:10.0.1.10", "properties": {}},
        {"id": "rel:ws2-has-ip", "type": "HAS_IP", "source_id": "device:ws-002", "target_id": "ip:10.0.1.20", "properties": {}},
        {"id": "rel:ws1-connects-ad", "type": "CONNECTS_TO", "source_id": "device:ws-001", "target_id": "server:ad-01", "properties": {"protocol": "SMB"}},
        {"id": "rel:ws1-connects-files", "type": "CONNECTS_TO", "source_id": "device:ws-001", "target_id": "server:files-01", "properties": {"protocol": "SMB"}},
        {"id": "rel:files-runs-portal", "type": "RUNS", "source_id": "server:files-01", "target_id": "app:portal", "properties": {}},
        {"id": "rel:alert-affects-ws1", "type": "AFFECTS", "source_id": "alert:2026-0001", "target_id": "device:ws-001", "properties": {}},
        {"id": "rel:alert-uses-t1078", "type": "USES_TECHNIQUE", "source_id": "alert:2026-0001", "target_id": "technique:T1078", "properties": {}},
        {"id": "rel:ws1-has-vuln", "type": "HAS_VULNERABILITY", "source_id": "device:ws-001", "target_id": "vuln:cve-2025-0001", "properties": {}},
        {"id": "rel:svc-admin-ad", "type": "ADMINISTERS", "source_id": "user:svc-backup", "target_id": "server:ad-01", "properties": {}},
    ]
    return nodes, relationships
