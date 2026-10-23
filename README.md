# Sibyl

An agent team that tells a security engineer which new vulnerabilities actually affect their software. It reconciles public vulnerability sources against a company's SBOM, keeps a source on every fact, and escalates uncertainty to a human.

This repository is the Open Agent Hackathon 2026 build. Planning lives in a local `docs/` folder that is not part of the git history.

## Stack

- Python 3.12 (uv), FastAPI, Postgres 16
- TypeScript engines for Meterless World Model and H-MEM (`engines/`), checked by the upstream conformance runners
- React, Vite, TypeScript, Tailwind, shadcn/ui

## Setup

```text
uv sync
docker compose up -d          # Postgres 16 on localhost:5434
cp .env.example .env          # then fill in Zetaris and Nightshift values locally
npm --prefix web install      # web/.npmrc sets legacy-peer-deps so npm 10 can resolve Vite 8
npm --prefix web run dev
```

Zetaris runs from its own Docker bundle. Meterless Nightshift is the installed desktop app. The NVIDIA key stays in Nightshift, not in `.env`.

## Commands

```text
uv run tests/smoke_test.py     # Zetaris web, Zetaris SQL, Nemotron reply
npm --prefix web run dev       # UI
```

Engine conformance runs from a local checkout of [Meterless/Meterless](https://github.com/Meterless/Meterless), pointed at `engines/world-model/src/index.ts` and `engines/hmem/src/index.ts`. Those modules are not implemented yet.

## Status

Foundations are scaffolded. Collectors, the Zetaris join, the agents, and the engines are still ahead. Sample company data is not in the tree yet.
