# SOC AutoPilot

**SOC AutoPilot — Autonomous AI agent that investigates Splunk security alerts in under 2 minutes**

## The Problem

SOC teams are overwhelmed by alert fatigue: analysts receive an average of 2,992 alerts per day, and 42% go uninvestigated. Breaches often begin in that gap, when real threats are buried under repetitive noise, false positives, and manual triage backlogs. SOC AutoPilot helps close the gap by automating the first-pass investigation workflow.

## How It Works

1. **Extract IOCs** from the alert description, including IP addresses, usernames, and domains.
2. **Check the knowledge base** for similar past investigations and known false-positive patterns.
3. **Pull live logs from Splunk** using Splunk MCP-compatible REST queries.
4. **Classify the threat with AI** using Gemini Flash and available log context.
5. **Generate an investigation report** with findings, verdict, severity, recommended actions, and SPL.
6. **Save the investigation** to the local knowledge base for future learning and analyst feedback.

## Demo

[Demo GIF coming soon]

YouTube video: [Coming soon](https://youtube.com/)

## Features

- Autonomous 6-step investigation pipeline
- Splunk MCP Server integration for live log queries
- Gemini Flash AI for threat classification
- Self-learning knowledge base (remembers past investigations)
- False positive detection from historical patterns
- Auto-generates SPL detection rules
- Analyst feedback loop
- Supports multiple AI backends (Gemini, Groq, Ollama)

## Architecture

```text
Alert Input
    |
    v
AutoPilot Agent
    |
    +--> Splunk MCP
    |       |
    |       v
    |   Live Log Queries
    |
    +--> Gemini Flash
    |
    +--> Knowledge Base
            |
            v
Report + SPL Rule
```

## Setup

### Prerequisites

- Python 3.10+
- Git
- Splunk Enterprise free trial

### 1. Clone Repo

```bash
git clone https://github.com/your-org/soc-autopilot.git
cd soc-autopilot
```

### 2. Run Installer

```bat
install.bat
```

### 3. Configure Environment

Copy `.env` and fill in:

```env
GEMINI_API_KEY=PASTE_YOUR_GEMINI_KEY_HERE
SPLUNK_TOKEN=PASTE_YOUR_SPLUNK_TOKEN_HERE
```

Get a Gemini API key from [Google AI Studio](https://aistudio.google.com/).

### 4. Install Splunk MCP Server

Install the Splunk MCP Server app from [Splunkbase](https://splunkbase.splunk.com/), then configure your Splunk token in `.env` and `config.yaml`.

## Usage

Test Splunk connectivity:

```bash
python main.py test
```

Investigate an alert:

```bash
python main.py investigate "Brute force attempt from 185.220.101.45 against admin account"
```

View investigation history:

```bash
python main.py history
```

Add analyst feedback:

```bash
python main.py feedback --id 1 --verdict FALSE_POSITIVE --note "Known scanner"
```

## AI Backends

| Backend | Status | Setup |
| --- | --- | --- |
| Gemini | Default | Add `GEMINI_API_KEY` to `.env` and set `ai.provider: gemini` in `config.yaml`. |
| Groq | Planned | Add a Groq API key and configure the Groq adapter when backend support is enabled. |
| Ollama | Planned | Install Ollama locally, pull a security-capable model, and configure the Ollama adapter when backend support is enabled. |

## Built For

Splunk Agentic Ops Hackathon 2026 — Security Track

## License

MIT
