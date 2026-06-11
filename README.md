# PkgScan

An end-to-end vulnerability monitoring system for developer endpoints: a local agent scans machines for project dependency files, a FastAPI backend checks every package against the [OSV.dev](https://osv.dev) vulnerability database, and a React dashboard shows each endpoint's security posture — including what could **not** be checked, so a partial scan never masquerades as a clean one.

```
┌──────────────┐   POST /api/scan    ┌──────────────────┐   query    ┌─────────┐
│  Agent (CLI) │ ──────────────────► │  FastAPI Server  │ ─────────► │ OSV.dev │
│  scans disk  │                     │  + SQLite cache  │ ◄───────── │   API   │
└──────────────┘                     └──────────────────┘            └─────────┘
                                              ▲
                                              │ GET /api/reports/{endpoint_id}
                                     ┌────────┴─────────┐
                                     │  React Dashboard │
                                     └──────────────────┘
```

## Supported ecosystems

| Ecosystem | Manifest file      | Notes                                              |
| --------- | ------------------ | -------------------------------------------------- |
| npm       | `package.json`     | `dependencies` + `devDependencies`                 |
| PyPI      | `requirements.txt` | Pinned (`==`) entries only; others skipped loudly  |

Parsers are registered in a filename → function dict (`PARSERS` in `agent.py`). Adding a new ecosystem means writing one parser function and one registry line — the directory-scanning logic is never touched.

## Quick start

Prerequisites: Python 3.13+, Node.js 18+.

**1. Server**

```bash
pip install -r requirements.txt
uvicorn main:app --reload          # http://127.0.0.1:8000 (docs at /docs)
```

**2. Agent** (second terminal)

```bash
python agent.py
```

Choose scan mode `3` (Custom) and point it at the bundled demo project:

```
examples/demo-project
```

It contains deliberately vulnerable pinned dependencies (npm + PyPI), so a scan returns real findings in seconds. The agent prints your endpoint ID when done.

**3. Dashboard** (third terminal)

```bash
cd pkgscan-frontend
npm install
npm run dev                        # http://localhost:5173
```

Search for your endpoint ID to see the report.

## How it works

1. **Agent** walks the chosen directories (skipping `node_modules`, virtualenvs, system folders), parses every manifest it has a registered parser for, de-duplicates the packages, and POSTs them to the server.
2. **Server** checks each package against a 24-hour cache; cache misses are queried against OSV.dev concurrently (`ThreadPoolExecutor`, 15 workers). Results are written both to the cache and to an immutable per-scan snapshot.
3. **Report** is served from the scan snapshot — what you see is what that scan actually found, even if newer data exists in the cache.

## Design decisions

**Scans are immutable snapshots.** Each scan stores its own per-package results (`scan_packages` table) instead of pointing at the live cache. Historical reports never change retroactively, and the report endpoint reads them back with two queries total — no per-package lookups.

**Failed checks are first-class, never silent.** If OSV can't be reached for a package (timeout, rate-limit, 5xx), that package is reported as *unchecked* — in the agent's terminal summary, in the API response (`failed_checks`), and on the dashboard (an "Incomplete Scan" status replaces the green badge). A scan that couldn't verify everything never claims everything is safe.

**Transient errors are not cached.** A failed check is a fact about the network, not about the package. Caching it would suppress re-checks for 24 hours and silently hide the package from reports — a false-negative window. Errors skip the cache entirely; the previous known-good result, if any, is preserved.

**Remediation advice is verified before it's given.** A suggested fix version is itself checked against OSV (to avoid recommending a version with known chained vulnerabilities), and pre-release versions (`alpha`, `beta`, `rc`) are never suggested.

**Unparseable input is skipped loudly.** Unpinned requirements (`flask>=2.0`), includes (`-r`), and editable installs can't be checked reliably against OSV, so the agent skips them **with a warning** rather than guessing or staying quiet.

## API

| Method | Endpoint                     | Description                                                                  |
| ------ | ---------------------------- | ---------------------------------------------------------------------------- |
| `POST` | `/api/scan`                  | Accepts `{endpoint_id, packages[]}`, runs cached/concurrent OSV checks, persists a scan snapshot, returns per-package results. |
| `GET`  | `/api/reports/{endpoint_id}` | Latest scan for an endpoint: vulnerabilities (with patched version when a safe one exists) and failed checks. |
| `GET`  | `/`                          | Health check.                                                                |

Interactive API docs (Swagger UI) are auto-generated at `http://127.0.0.1:8000/docs`.

## Project structure

```
agent.py                      # CLI agent: directory walking + parser registry
main.py                       # FastAPI app: scan endpoint, OSV client, report endpoint
models.py                     # SQLAlchemy models: scans, scan_packages, vulnerability_cache
database.py                   # Engine / session setup (SQLite)
examples/demo-project/        # Deliberately vulnerable manifests for demos & testing
pkgscan-frontend/             # React + Vite dashboard
```

## Tech stack

**Backend:** Python, FastAPI, SQLAlchemy, SQLite · **Agent:** Python, Rich · **Frontend:** React, Vite, lucide-react · **Data source:** [OSV.dev](https://osv.dev) (Google Open Source Vulnerabilities)

## Roadmap

- Test suite (pytest) with a mocked OSV client
- Dashboard-triggered scans (agent as a polling service with a job queue)
- Re-scan failed checks only
- Show last known result for packages whose current check failed
- Lock-file parsing (`package-lock.json`, `poetry.lock`) for resolved versions
- Async scan endpoint + OSV batch queries
- Database migrations (Alembic) ahead of a PostgreSQL move
