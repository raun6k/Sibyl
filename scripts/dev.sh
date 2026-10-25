#!/usr/bin/env bash
# Postgres, FastAPI, and Vite. Zetaris and Nightshift are already running.
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose up -d
uv run python -m sibyl.api &
api_pid=$!
cleanup() {
  kill "$api_pid" 2>/dev/null || true
}
trap cleanup EXIT
npm --prefix web run dev
