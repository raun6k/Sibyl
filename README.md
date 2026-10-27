# Sibyl

**Which new vulnerabilities actually affect your software?**

Sibyl is a team of agents that answers that question for your own code. Connect a repository and Sibyl finds your services and the exact package versions they run, reconciles seven public vulnerability sources against them, and tells you what to patch first. Every verdict cites the source record behind it. When the evidence falls short, Sibyl asks you instead of guessing, and it remembers your answer.

Built for the Open Agent Hackathon 2026, Track 1: Solving Fragmented Intelligence.

## The problem

Vulnerability data is scattered and it disagrees. OSV, GitHub Advisories, NVD, CVE.org, CISA KEV, FIRST EPSS and ENISA EUVD each describe the same flaw differently: different package names, different version ranges, and sometimes plain mistakes. In 2026 NVD stopped enriching most new CVEs with the CPE data that legacy scanners depend on, so a pipeline built on NVD alone now misses more than half of the real problems.

A security engineer ends up reading four advisories to settle one CVE, for one package, in one service. Then they do it again next week.

## How you work with Sibyl

1. **Connect a repository.** Sibyl scans the tree with `cdxgen` and makes a service of every folder with its own manifest (npm, PyPI, Maven, Go), with the exact versions it runs.
2. **Confirm what it worked out.** From the code it read, Sibyl proposes each service's exposure, owner, criticality and data, and asks you to confirm them in the Inbox. Those answers weight every priority after that.
3. **Let the agents triage.** Six agents reconcile the seven sources against your packages. Every step is recorded in the run trace.
4. **Patch what matters.** The patch list ranks cases by known exploitation, EPSS, CVSS and how exposed the service is, and shows which sources agree with each verdict.
5. **Check any verdict.** A case file shows every fact with the record it came from, and which source won when they disagreed.
6. **Answer what it can't settle.** Conflicting or thin evidence goes to *Needs you* with each source's position side by side.
7. **It remembers.** Your answer decides the same case in later runs. Trust in each source changes only when you approve it.
8. **It keeps watching.** Sibyl re-scans when code changes, refreshes the feeds and re-triages on a schedule, reusing every verdict whose inputs didn't change.

The UI has a guided tour of exactly this flow: open it with **Explore the demo**. It uses a sample company with four services, so no repository is needed.

## The agents

| Agent | What it does |
|---|---|
| **Scout** | Plans the run from the request: a full triage, one service, or a single CVE question. |
| **Mapper** | Links advisories to your packages, across aliases and naming schemes. |
| **Matcher** | Evaluates version ranges, and reads the advisory text when there is no structured range. |
| **Critic** | Challenges each draft verdict: source authority, disagreements, withdrawn records, unsupported quotes. Sends weak cases back to the Mapper or Matcher. |
| **Prioritiser** | Scores what is affected with exploitation, EPSS, CVSS and your service's exposure, and routes low-confidence cases to you. |
| **Reporter** | Writes the patch list, the briefing and the case files. |

The agents talk through structured messages in a shared World Model, so every claim, conflict and send-back is traceable.

## Built on

- **Zetaris** is the data layer. It federates Sibyl's Postgres with live REST tables for KEV, EPSS and EUVD, and joins them with your inventory in one query, `v_candidate_matches`. The inventory is a Zetaris Unified Semantic Layer model with data-quality rules that run after every sync.
- **Meterless** provides the World Model, which holds case state, and H-MEM, which holds the trust ledger and your resolutions. Both are our own TypeScript implementations in `engines/`; they pass the upstream conformance suites 8/8 and 13/13. Nightshift routes every model call.
- **NVIDIA Nemotron** answers every model call, through a Nemotron-only fleet in Nightshift. Only manifest excerpts are sent, never whole files.
- Python 3.12, FastAPI, Postgres 16, and React with Vite, Tailwind and shadcn/ui.

## Results

Measured on the sample workspace (4 services, 689 cases) against 40 hand-labelled gold pairs. Each label comes from the upstream fix commit, never from Sibyl's output.

| | Sibyl |
|---|---|
| Recall: real vulnerabilities found | **100%** (26 of 26) |
| Precision | **92.9%** |
| Accuracy | **92.5%** |
| Verdicts that cite a source record | **689 of 689** |
| Tokens per case | **361** |
| Re-run of an unchanged repository | **69 of 69** verdicts reused, zero model calls |

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="eval/results/charts/dark/07-case-file-validator.png">
  <img alt="A case file: NVD's range is a typo, the Critic sends the case back, and the Matcher quotes NVD's own description" src="eval/results/charts/light/07-case-file-validator.png">
</picture>

Here, NVD's version range for validator is a typo that contradicts NVD's own description. The Critic catches the contradiction and sends the case back, and the Matcher re-reads the description and quotes it.

Sibyl is built to fail safe. With any one of the seven sources switched off, the run still finishes and is marked degraded. With OSV down, Sibyl sends 18 cases to a human instead of 3: it gets more careful, not wrong. Instructions planted in an advisory are quarantined before they reach a model.

Every number is reproducible. [`eval/README.md`](eval/README.md) explains how, and the full tables are in [`eval/results/`](eval/results/).

## Run it

You need Python 3.12 with [uv](https://docs.astral.sh/uv/), Node 20 or later, Docker, a running Zetaris and Meterless Nightshift.

```text
uv sync
npm --prefix engines install
npm --prefix web install
docker compose up -d          # Postgres 16 on localhost:5434
cp .env.example .env          # then fill in the Zetaris and Nightshift values
uv run scripts/setup.py       # build engines, seed Postgres, ingest the sample, register it in Zetaris
uv run tests/smoke_test.py    # checks Zetaris and a Nemotron reply
scripts/dev.sh                # API on :8000, UI on http://localhost:5173
```

- **Zetaris** runs from its own Docker bundle. Put its REST URL, org id and API key in `.env`. Its query engine reaches Postgres at `host.docker.internal:5434`; set `ZETARIS_PG_HOST` and `ZETARIS_PG_PORT` if yours is reached another way.
- **Meterless Nightshift** is the desktop app. Create a Sibyl fleet under NIGHT → LANES with Nemotron lanes only (Nemotron 3.5 Lightning and Nemotron 3 Nano to race, Nemotron 3.5 Super VL to judge, Nemotron 3 Ultra to verify), then copy the runtime token into `METERLESS_RUNTIME_TOKEN`. The NVIDIA key stays in Nightshift.
- For live repositories, `GITHUB_TOKEN` (private repos, higher GitHub Advisories limits) and `NVD_API_KEY` are optional. `SIBYL_SCHEDULER=false` turns off scheduled syncs and triages.

Then open the UI and either connect a repository or press **Explore the demo**.

### More commands

```text
uv run scripts/run_demo.py --label fixtures      # headless triage; report and trace in output_examples/
uv run pytest                                    # unit tests
uv run tests/robustness_check.py                 # one outage per source, plus idempotency
uv run eval/collect_runs.py && uv run eval/run_eval.py   # re-run the eval
```

## What's in the repo

| Path | |
|---|---|
| `sibyl/` | Agents, orchestrator, job queue and scheduler, API |
| `engines/` | World Model and H-MEM engines (TypeScript) |
| `web/` | The UI |
| `zetaris/sql/` | Zetaris datasources, REST tables and views |
| `prompts/` | Versioned agent prompts |
| `output_examples/` | Example reports and full agent traces |
| `eval/` | Gold set, eval harness and results |
| `data/sample/` | The sample company's SBOMs and source snapshots |
