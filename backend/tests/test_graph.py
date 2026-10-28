from backend.app.graph_schema import CONSTRAINT_QUERIES, EXAMPLE_QUERIES
from backend.app.neo4j_repository import GraphRepository
from backend.app.synthetic_data import synthetic_graph


class FakeResult:
    def __init__(self, count: int) -> None:
        self.count = count

    def single(self) -> dict[str, int]:
        return {"count": self.count}


class FakeSession:
    def __init__(self) -> None:
        self.queries: list[tuple[str, dict[str, object]]] = []

    def __enter__(self) -> "FakeSession":
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def run(self, query: str, **parameters: object) -> FakeResult:
        self.queries.append((query, parameters))
        records = parameters.get("nodes") or parameters.get("relationships")
        return FakeResult(len(records) if records else 1)


class FakeDriver:
    def __init__(self) -> None:
        self.session_instance = FakeSession()

    def session(self) -> FakeSession:
        return self.session_instance


def test_synthetic_fixture_is_deterministic() -> None:
    assert synthetic_graph() == synthetic_graph()
    nodes, relationships = synthetic_graph()
    assert len(nodes) == 12
    assert len(relationships) == 11


def test_seed_uses_constraints_and_parameterized_upserts() -> None:
    driver = FakeDriver()
    nodes, relationships = synthetic_graph()

    counts = GraphRepository(driver).seed(nodes, relationships)

    assert counts == (12, 11)
    queries = driver.session_instance.queries
    assert len(queries) == len(CONSTRAINT_QUERIES) + 8 + 8
    assert all("$" not in query for query, _ in queries[: len(CONSTRAINT_QUERIES)])
    upserts = queries[len(CONSTRAINT_QUERIES) :]
    assert all(parameters for _, parameters in upserts)
    assert all("MERGE" in query for query, _ in upserts)
    assert all("CREATE" not in query for query, _ in upserts)


def test_example_queries_are_parameterized_and_do_not_infer_compromise() -> None:
    assert set(EXAMPLE_QUERIES) == {"alerts_for_device", "assets_for_user", "candidate_paths", "blast_radius"}
    assert all("$" in query for query in EXAMPLE_QUERIES.values())
    assert "compromised" not in EXAMPLE_QUERIES["candidate_paths"]


def test_duplicate_records_are_sent_once_for_idempotent_imports() -> None:
    driver = FakeDriver()
    nodes, relationships = synthetic_graph()

    counts = GraphRepository(driver).seed(nodes + nodes[:2], relationships + relationships[:2])

    assert counts == (12, 11)
    upserts = driver.session_instance.queries[len(CONSTRAINT_QUERIES) :]
    node_batches = [parameters["nodes"] for query, parameters in upserts if "nodes" in parameters]
    relationship_batches = [
        parameters["relationships"] for query, parameters in upserts if "relationships" in parameters
    ]
    assert sum(len(batch) for batch in node_batches) == 12
    assert sum(len(batch) for batch in relationship_batches) == 11
