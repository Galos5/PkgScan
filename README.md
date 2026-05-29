# PkgScan 🚀

PkgScan is an enterprise-grade vulnerability scanning system designed to detect security flaws in open-source packages across developer endpoints. The system consists of a lightweight, secure local agent, a high-performance FastAPI backend, and an interactive React web dashboard that visualizes security posture and provides safe remediation advice.

## Architecture Overview

The system is built with a focus on performance, scalability, and security:

* **PkgScan Agent (`agent.py`)**: A lightweight client that recursively scans specified directories for `package.json` files, extracts dependency metadata surgically without risking data leaks, and securely transmits payloads using an adaptive timeout algorithm.
* **PkgScan Server (`main.py`)**: A FastAPI backend that coordinates vulnerability lookups, stores comprehensive scan histories using SQLAlchemy with SQLite, and minimizes external network overhead through an optimized caching strategy.
* **React Dashboard (`App.jsx`)**: A beautiful, responsive Dark-Mode UI that connects to the backend API, displays active endpoint vulnerabilities, and presents clear remediation advice for engineers.

## Key Engineering Features

### 1. High-Performance Concurrency (Thread Pool)
To solve the $N+1$ query bottleneck during cold-start cache misses, the backend implements a concurrent lookup engine using Python's `concurrent.futures.ThreadPoolExecutor`. Instead of executing sequential blocking HTTP requests to the Google OSV API, the server fires parallel workers (up to 15 concurrent threads). This optimization reduced total processing time for large-scale scans (100+ packages) from **~55 seconds down to under 3 seconds**.

### 2. Strict Remediation Validation (Anti-Chained Vulnerabilities)
Unlike basic scanning tools that blindly suggest the next available version, PkgScan implements a **Strict Recursive Verification Loop**. When a potential fix version is extracted from Google OSV, the backend automatically queries the API *again* to verify that the suggested patch does not introduce new or chained vulnerabilities. If a patch exists but contains flaws, the system flags it accordingly.

### 3. Pre-Release & Unstable Version Filtering
The backend remediation engine automatically purges and skips `beta`, `alpha`, `rc` (Release Candidates), and `pre` versions from its upgrade advice. This ensures that enterprise developers are never prompted to install unstable packages into critical systems.

### 4. Adaptive Client-Side Timeout
To prevent premature request drops while maintaining resource efficiency, the agent calculates a dynamic network timeout based on the input payload size:
$$\text{Timeout} = 5s + (\text{Number of Packages} \times 0.5s)$$
This gives the server the necessary breathing room to process bulk imports during cache misses, while enforcing strict, short constraints for smaller, everyday scans.

### 5. Surgical Zero-Leak Directory Scanning
The local agent enforces a strict $O(1)$ filename filter matching only exact configuration targets (`package.json`). It completely avoids reading raw source code, assets, or personal binaries, preventing data exfiltration and ensuring a zero-leak pipeline.

### 6. Smart Caching Layer & SQL Join Optimization
The backend implements a 24-hour Time-To-Live (TTL) cache. For data rendering, the targeted security reporting endpoint (`GET /api/reports/{endpoint_id}`) avoids iterative database queries by performing a singular, highly efficient relational join between the scan history and the vulnerability cache tables.

## API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/scan` | Receives endpoints dependencies, executes concurrent OSV lookups, populates cache, and logs scan history. |
| `GET` | `/api/reports/{endpoint_id}` | Returns a refined, high-priority security report containing only `VULNERABLE` assets for a specific machine. |
| `GET` | `/` | Health check endpoint confirming server operational status. |

## Tech Stack

* **Frontend**: React.js, Vite, Lucide Icons, Custom CSS Matrix
* **Backend**: FastAPI, Uvicorn, Concurrent Threading
* **Database & ORM**: SQLite, SQLAlchemy
* **Networking**: Requests (Python), Fetch API (JavaScript)
