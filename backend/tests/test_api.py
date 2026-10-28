from dataclasses import replace

from fastapi.testclient import TestClient

from backend.app import api
from backend.app.config import settings
from backend.app.main import app


def test_api_does_not_fabricate_graph_when_neo4j_is_not_configured(monkeypatch) -> None:
    monkeypatch.setattr(
        api,
        "settings",
        replace(settings, neo4j_username="", neo4j_password=""),
    )
    response = TestClient(app).get("/api/graph")

    assert response.status_code == 503
    assert response.json()["detail"] == "Neo4j credentials are not configured."


def test_sources_only_reports_connected_after_database_query(monkeypatch) -> None:
    monkeypatch.setattr(
        api,
        "settings",
        replace(settings, neo4j_username="", neo4j_password=""),
    )

    response = TestClient(app).get("/api/sources")

    assert response.status_code == 503
    assert response.json()["detail"] == "Neo4j credentials are not configured."
