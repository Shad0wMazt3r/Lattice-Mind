# Installation Methods

Lattice Mind supports three primary installation methods depending on your use case: Local Development, Docker, or Cloud Deployment (DigitalOcean).

## 1. Standalone (Local Python)

Best for active development of core logic and Python-based decision trees.

### Steps:
1.  **Create a Virtual Environment**
    ```powershell
    python -m venv venv
    .\venv\Scripts\Activate.ps1
    ```

2.  **Install Dependencies**
    Install the package in editable mode with development extras:
    ```powershell
    python -m pip install -e ".[dev]"
    ```

3.  **Run the API**
    ```powershell
    uvicorn lattice_mind.api.server:app --host 0.0.0.0 --port 8000
    ```

---

## 2. Docker (Containerized)

Recommended for a consistent environment with all security tool adapters pre-configured.

### Configuration Files:
*   **Dockerfile**: Uses a multi-stage build to include necessary security binaries (curl, ffuf, etc.) and the Python runtime.
*   **docker-compose.yml**: Orchestrates the API and **Mailpit** (for SMTP capture).

### Commands:
**Build and Start:**
```powershell
docker compose build lattice-mind-api
docker compose up -d
```

**View Logs:**
```powershell
docker compose logs -f lattice-mind-api
```

---

## 3. DigitalOcean Deployment

Lattice Mind is designed to be easily deployed to DigitalOcean via the **App Platform** or a **Droplet**.

### Method A: App Platform (Managed)
1.  Connect your repository to DigitalOcean.
2.  The platform will automatically detect the [Dockerfile](file:///c:/Users/er123/OneDrive/Desktop/Projects/copilot/Dockerfile) and build the image.
3.  **Environment Variables**: You must configure the following in the DO Dashboard:
    *   `LATTICE_MIND_DB`: Set to [/data/runs.db](file:///data/runs.db) (Ensure a volume is attached to `/data`).
    *   `LATTICE_MIND_API_BASE_URL`: Your public app URL.
    *   `LATTICE_MIND_MCP_TOKEN`: Your secret token for AI integration.
4.  Expose port `8000`.

### Method B: Droplet (Docker Compose)
1.  Provision a "Docker on Ubuntu" Droplet.
2.  SSH into the droplet and clone the repo.
3.  Run `docker compose -f docker-compose.yml up -d`.

### Required Environment Variables
| Variable | Description | Recommended Value |
| :--- | :--- | :--- |
| `LATTICE_MIND_LOG_LEVEL` | Verbosity of logs | `info` (prod) or `debug` |
| `LATTICE_MIND_DB` | Path to SQLite DB | `/data/runs.db` |
| `SMTP_HOST` | SMTP server for alerts | `mailpit` or external provider |
| `SMTP_PORT` | SMTP port | `1025` |

---

> [!WARNING]
> When deploying to DigitalOcean, ensure the `/data` directory is mounted to a **persistent volume**, or your run history will be lost on every deployment.
