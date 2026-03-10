#!/usr/bin/env pwsh
# dev.ps1 — Start lattice-mind in hot-reload dev mode
# Usage: .\dev.ps1

Write-Host "🚀 Starting Lattice-Mind in dev (hot-reload) mode..." -ForegroundColor Cyan
Write-Host "   Any change to a .py file will be picked up instantly." -ForegroundColor DarkGray
Write-Host "   Press Ctrl+C to stop.`n" -ForegroundColor DarkGray

# Build first if the dev image doesn't exist yet, then bring it up
docker compose --profile dev up --build
