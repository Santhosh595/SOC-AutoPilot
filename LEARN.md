# Learn — SOC-AutoPilot

## What it is

Autonomous SOC (Security Operations Center) triage agent. Takes a Splunk alert, investigates it with SPL queries, classifies severity, and drafts a detection rule. Shrinks 45-minute manual triage to under 2 minutes. Uses a Splunk MCP server + hosted model + knowledge base.

**Read this first, then go file-by-file in the repo.**

## 5-minute quickstart

```bash
git clone https://github.com/Santhosh595/SOC-AutoPilot && cd SOC-AutoPilot
pip install -r requirements.txt
cp .env.example .env   # fill Splunk/model keys — never commit .env
python -m soc_autopilot --help   # check README for exact entrypoint
pytest -q
```

## Concepts — the "why" behind each file

| If you see this in the code | What it means | Viva answer |
|---|---|---|
| Splunk alert input | The trigger event | Alert = signal, not incident. Triage decides which |
| SPL query generation | `index=... sourcetype=... | stats count` | Investigation queries must be validated before running |
| Severity scoring | Critical/High/Medium/Low | Based on asset criticality + behavior + confidence |
| MITRE ATT&CK mapping | Technique classification | e.g. T1078 (valid accounts) — the shared language |
| Detection rule draft (Sigma/SPL) | The output artifact | A finding without a rule is a missed lesson |
| Knowledge base lookup | Past incidents for context | Reduces repeat work; also a poisoning risk |
| Human approval gate | Safety boundary | Automation proposes, human decides |

## Common pitfalls

1. **Running LLM-generated SPL blindly** — hallucinated field names = wasted queries or worse. Validate syntax first.
2. **Leaking sensitive data to the model** — alerts contain IPs, usernames, maybe keys. Strip before sending.
3. **No confidence calibration** — "severity: high" with no basis erodes trust. Show the rubric.
4. **Alert fatigue, automated** — auto-closing everything is worse than not automating.
5. **Knowledge base poisoning** — if the KB is writable by the agent, it can "learn" false lessons. Audit it.

## Hands-on, in this order

1. Map the pipeline: alert in → (enrich → investigate → classify → draft) → out. Draw it.
2. Run one investigation manually in Splunk (search `index=* | head 20` — see the shape of data).
3. Read the severity rubric in the code. Pick a sample alert, score it by hand. Does it match?
4. Find the ATT&CK mapping. Look up 2 techniques at https://attack.mitre.org/ — read the detection guidance.
5. Check: where does a human approve? What happens if they reject?
6. Write one Sigma rule by hand for that alert: https://sigmahq.com/docs/ (start with "failed logins > 10/min")

## Viva questions (with the trap)

1. **"Walk the pipeline end to end."** Answer: alert → context fetch → SPL investigation → ATT&CK classify → severity → draft rule → human review. Trap: skipping the human.
2. **"How is severity scored?"** Answer: asset criticality + behavior rarity + confidence; thresholds define escalate vs auto-close.
3. **"Map an alert to ATT&CK."** Answer with a concrete technique ID + tactic. Prepare one example.
4. **"Why not fully auto?"** Answer: hallucinated queries, accountability, blast radius. Autonomy with a gate.
5. **"How do you validate LLM SPL?"** Answer: parse/syntax check + dry-run + field allow-list.

## 3 things to say if stuck

- "Every step is logged; the human gate is before any action."
- "The knowledge base speeds up familiar alerts; new ones get investigated fresh."
- "Severity has a written rubric in the code — I can show you."

Good luck. SOC is a real job path — this repo proves you know the workflow, not just the tools.
