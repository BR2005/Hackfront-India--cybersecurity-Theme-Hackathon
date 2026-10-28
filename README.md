# GraphOps

GraphOps is a security graph operations platform. Phase 1 establishes the
frontend and backend foundations; dashboard features will be added in later
phases.

## Prerequisites

- Node.js 20 or newer and npm
- Python 3.11 or newer

## Configuration

Copy the example environment file before starting either service:

```powershell
Copy-Item .env.example .env
```

The frontend reads `VITE_API_URL`. The backend reads `APP_ENV`, `APP_HOST`,
`APP_PORT`, and the Neo4j connection settings. Database credentials are
intentionally blank in the example and must never be committed to source
control.

## Frontend

```powershell
npm install
npm run dev
```

The Vite development server is available at `http://localhost:5173`.

## Backend

Create and activate a virtual environment, then install the dependencies:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r backend\requirements.txt
```

Start the API:

```powershell
python -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

Verify the health endpoint:

```powershell
Invoke-RestMethod http://localhost:8000/health
```

Run backend tests from the repository root:

```powershell
python -m pytest backend\tests
```

## Neo4j graph seed

Start a Neo4j 5.x instance, set `NEO4J_URI`, `NEO4J_USERNAME`, and
`NEO4J_PASSWORD` in `.env`, then run:

```powershell
python -m backend.scripts.seed_graph
```

The seed creates uniqueness constraints and imports the deterministic fixture
using the official Neo4j Python driver. Nodes and relationships use stable IDs
and `MERGE`, so rerunning the command is safe and does not create duplicates.
See [docs/graph-schema.md](docs/graph-schema.md) for labels, relationship
semantics, evidence boundaries, and parameterized Cypher examples.

## Validation

```powershell
npm run build
python -m pytest backend\tests
```

## Frontend investigation surfaces

The frontend provides responsive routes for:

- Overview command center
- Interactive Cytoscape.js attack graph
- Blast-radius analysis with 1, 2, and 3 hop limits
- Threat hunting and alert correlation
- Incident investigation
- Asset inventory
- Data-source and connection status

The default frontend mode calls the FastAPI read-only routes:
`/api/graph`, `/api/overview`, `/api/blast-radius`, `/api/alerts`,
`/api/assets`, and `/api/sources`. If Neo4j is unavailable, the UI shows an
error and no findings are fabricated. Use the **Enter demo mode** control, or
open the frontend with `?demo=true`, to explicitly explore the deterministic
fixture from `backend/app/synthetic_data.py`.
