# SOC AutoPilot Project Summary

## Overview

SOC AutoPilot is an autonomous AI security investigation agent for Splunk alerts. It extracts indicators of compromise, queries Splunk or demo data, classifies threats with Gemini Flash, remembers past investigations in SQLite, and generates analyst-ready reports plus SPL detection rules.

The project is built for the Splunk Agentic Ops Hackathon 2026 Security Track.

## Core Value

SOC teams face thousands of daily alerts, and many go uninvestigated because analysts are overloaded. SOC AutoPilot automates the first investigation pass so analysts can quickly see the likely verdict, severity, supporting evidence, recommended action, and detection rule.

## Investigation Flow

1. Alert description is passed into the CLI.
2. `AutoPilotAgent` extracts IOCs such as IP addresses, usernames, and domains.
3. The knowledge base checks for similar past cases and known false-positive patterns.
4. Splunk is queried for live events, or demo mode returns local fake results.
5. Gemini Flash classifies the alert and generates a report plus SPL rule.
6. The investigation is saved to SQLite and report artifacts are written to `reports/`.

## Architecture

```text
Alert Input
    |
    v
AutoPilot Agent
    |
    +--> Splunk MCP Server / Demo Mode Logs
    |
    +--> Gemini Flash AI
    |
    +--> Knowledge Base (SQLite)
    |
    v
Reports + SPL Rules
```

## Main Components

| File | Purpose |
| --- | --- |
| `main.py` | CLI entry point for investigating alerts, testing Splunk, viewing history, and adding feedback. |
| `agent/autopilot.py` | Main orchestration loop for IOC extraction, log collection, AI analysis, reporting, and persistence. |
| `agent/mcp_client.py` | Splunk REST client with demo-mode fallback data. |
| `agent/llm_adapter.py` | Gemini API adapter for classification, SPL generation, and report generation. |
| `agent/knowledge_base.py` | SQLite-backed investigation history and false-positive pattern store. |
| `agent/reporter.py` | Saves markdown reports and SPL files, and prints Rich summary tables. |
| `sample_data/generate_sample_logs.py` | Generates fake security scenarios and ingests them into Splunk HEC. |
| `sample_data/sample_alerts.json` | Ready-made demo alerts matching the fake scenarios. |
| `create_architecture.py` | Generates `architecture.png` using matplotlib. |
| `config.yaml` | Project configuration for Splunk, AI model, agent behavior, output paths, and demo mode. |
| `.env` | Local secrets such as `GEMINI_API_KEY` and `SPLUNK_TOKEN`. |

## CLI Commands

Test Splunk or demo-mode connectivity:

```bash
python main.py test
```

Run an investigation:

```bash
python main.py investigate "Brute force attempt from 185.220.101.45 against admin account"
```

Show the latest investigations:

```bash
python main.py history
```

Add analyst feedback:

```bash
python main.py feedback --id 1 --verdict FALSE_POSITIVE --note "Known scanner"
```

Generate the architecture image:

```bash
python create_architecture.py
```

Generate and ingest sample logs into Splunk:

```bash
python sample_data/generate_sample_logs.py
```

## Configuration

`config.yaml` controls the main runtime behavior:

- `demo_mode`: when `true`, Splunk calls are skipped and local demo events are returned.
- `splunk`: host, port, token, and SSL verification settings.
- `ai`: provider and Gemini model name.
- `agent`: investigation limits and confidence threshold.
- `output`: report and log directories.

`.env` stores local secrets:

```env
GEMINI_API_KEY=PASTE_YOUR_GEMINI_KEY_HERE
SPLUNK_TOKEN=PASTE_YOUR_SPLUNK_TOKEN_HERE
```

## Demo Scenarios

The project includes three demo-ready security scenarios:

- Brute force attack from `185.220.101.45` against `admin`.
- Suspicious encoded PowerShell execution by `jsmith` on `WORKSTATION-04`.
- Data exfiltration pattern by `svc_backup` to `203.0.113.99`.

These scenarios can be investigated through real Splunk sample ingestion or through `demo_mode: true`.

## Generated Artifacts

SOC AutoPilot creates:

- Markdown incident reports in `reports/`.
- SPL detection rules in `reports/`.
- Investigation history in `soc_autopilot.db`.
- Architecture diagram as `architecture.png`.

Runtime artifacts such as `.env`, logs, reports, virtual environments, and SQLite databases are ignored by Git.

## Dependencies

The project uses:

- `requests` for Splunk REST and HEC calls.
- `pyyaml` for configuration loading.
- `python-dotenv` for local environment secrets.
- `google-genai` / `google-generativeai` for Gemini integration.
- `mcp` for future MCP compatibility.
- `rich` for CLI tables, panels, and progress output.
- `urllib3` for SSL warning handling.
- `matplotlib` for architecture diagram generation.

## Current Status

The project has a complete working Python CLI skeleton, demo data path, Splunk REST integration, Gemini adapter, SQLite knowledge base, reporting helpers, architecture image generator, and professional README.

Next useful improvements would be adding automated tests, adding first-class Groq/Ollama adapters, and wiring richer similarity scoring in the knowledge base.
