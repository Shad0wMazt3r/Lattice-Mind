# Getting Started

This guide covers the initial steps required to set up the Lattice Mind environment for development or production use.

## Prerequisites

Before installing Lattice Mind, ensure your system meets the following requirements:

### Languages & Runtimes
*   **Python 3.11+**: The core engine and API are built with Python.
*   **Node.js (Optional)**: Required only if you intend to rebuild the frontend assets manually.

### Tools & Utilities
*   **Git**: For repository management.
*   **Docker & Docker Compose**: Recommended for consistent deployment and local development (includes Mailpit for email testing).
*   **Standard Security Tools**: The engine relies on external adapters for certain tasks (e.g., `curl`, `nmap`, `ffuf`). These are bundled in the Docker image.

### API Keys & Configuration
While Lattice Mind is deterministic and runs locally, some decision trees may require external configuration:
*   **SMTP Credentials**: For notification-based trees (configured via environment variables).
*   **MCP Tokens**: For securing the Model Context Protocol server integration.

## Initial Setup

1.  **Clone the Repository**
    ```bash
    git clone <proprietary-repo-url>
    cd copilot
    ```

2.  **Verify the Environment**
    Check that Python is correctly installed:
    ```bash
    python --version # Should be 3.11 or higher
    ```

3.  **Explore the Structure**
    Familiarize yourself with the core directories:
    *   `lattice_mind/core/`: The heart of the orchestration logic.
    *   `lattice_mind/trees/yaml/`: The library of executable exploitation trees.
    *   `lattice_mind/api/`: The FastAPI backend.
    *   `frontend/`: The dashboard source code.

---

> [!NOTE]
> Always use a virtual environment when installing outside of Docker to prevent dependency conflicts.
