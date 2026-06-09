"""
Run this once before demo to populate Splunk with sample data.
"""

import json
import os
import random
from datetime import datetime, timedelta

import requests
import yaml
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table


HEC_URL = "http://localhost:8088/services/collector/event"


def load_config(config_path=None):
    """Load project configuration from config.yaml."""
    if config_path is None:
        config_path = os.path.join(os.path.dirname(__file__), "..", "config.yaml")
    if not os.path.exists(config_path):
        return {}

    with open(config_path, "r", encoding="utf-8") as config_file:
        return yaml.safe_load(config_file) or {}


def get_splunk_token(config):
    """Return the Splunk token from environment or config."""
    return os.getenv("SPLUNK_TOKEN") or config.get("splunk", {}).get("token", "")


def build_hec_event(event_time, sourcetype, source, event):
    """Build a Splunk HEC event payload."""
    return {
        "time": event_time.timestamp(),
        "sourcetype": sourcetype,
        "source": source,
        "index": "main",
        "event": event,
    }


def generate_brute_force_events():
    """Generate failed and successful login events for a brute force scenario."""
    events = []
    start_time = datetime.utcnow() - timedelta(hours=2)
    source_ip = "185.220.101.45"
    username = "admin"

    for index in range(50):
        event_time = start_time + timedelta(minutes=index * 2)
        events.append(
            build_hec_event(
                event_time,
                "WinEventLog:Security",
                "windows_security",
                {
                    "scenario": "Brute Force Attack",
                    "EventCode": 4625,
                    "action": "failure",
                    "signature": "An account failed to log on",
                    "src_ip": source_ip,
                    "user": username,
                    "host": "DC-01",
                    "failure_reason": "Unknown user name or bad password",
                    "logon_type": 3,
                },
            )
        )

    events.append(
        build_hec_event(
            datetime.utcnow() - timedelta(minutes=1),
            "WinEventLog:Security",
            "windows_security",
            {
                "scenario": "Brute Force Attack",
                "EventCode": 4624,
                "action": "success",
                "signature": "An account was successfully logged on",
                "src_ip": source_ip,
                "user": username,
                "host": "DC-01",
                "logon_type": 3,
            },
        )
    )
    return events


def generate_powershell_events():
    """Generate suspicious PowerShell process creation events."""
    events = []
    encoded_commands = [
        "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
        "JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA",
        "cABvAHcAZQByAHMAaABlAGwAbAAgAC0AZQBuAGMAbwBkAGUAZABjAG8AbQBtAGEAbgBkAA==",
        "VwByAGkAdABlAC0ASABvAHMAdAAgACcAcgBlAG0AbwB0AGUAIABzAGMAcgBpAHAAdAAnAA==",
        "UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAHAAbwB3AGUAcgBzAGgAZQBsAGwALgBlAHgAZQA=",
    ]

    for index, encoded_command in enumerate(encoded_commands):
        event_time = datetime.utcnow() - timedelta(minutes=45 - (index * 4))
        events.append(
            build_hec_event(
                event_time,
                "WinEventLog:Security",
                "windows_process",
                {
                    "scenario": "Suspicious PowerShell",
                    "EventCode": 4688,
                    "user": "jsmith",
                    "host": "WORKSTATION-04",
                    "process_name": "powershell.exe",
                    "parent_process": "explorer.exe",
                    "command_line": f"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded_command}",
                    "process_id": random.randint(3000, 9000),
                },
            )
        )
    return events


def generate_exfiltration_events():
    """Generate large outbound network connection events."""
    events = []

    for index in range(10):
        event_time = datetime.utcnow() - timedelta(minutes=30 - (index * 2))
        events.append(
            build_hec_event(
                event_time,
                "stream:tcp",
                "network_traffic",
                {
                    "scenario": "Data Exfiltration Pattern",
                    "action": "allowed",
                    "direction": "outbound",
                    "src_ip": "10.10.4.25",
                    "dest_ip": "203.0.113.99",
                    "dest_port": 443,
                    "user": "svc_backup",
                    "host": "BACKUP-SRV-01",
                    "bytes_out": random.randint(50000001, 125000000),
                    "protocol": "tcp",
                },
            )
        )
    return events


def ingest_events(events, token, console):
    """Ingest HEC events into Splunk and return the number successfully sent."""
    headers = {
        "Authorization": f"Splunk {token}",
        "Content-Type": "application/json",
    }
    success_count = 0

    for event in events:
        try:
            response = requests.post(
                HEC_URL,
                headers=headers,
                data=json.dumps(event),
                timeout=10,
            )
            response.raise_for_status()
            success_count += 1
        except Exception as error:
            console.print(f"[red]Failed to ingest event: {error}[/red]")

    return success_count


def print_summary(summary, console):
    """Print a Rich summary table for generated sample data."""
    table = Table(title="Sample Security Logs Ingested")
    table.add_column("Scenario", style="cyan")
    table.add_column("Events Created", justify="right", style="green")

    for scenario, count in summary.items():
        table.add_row(scenario, str(count))

    console.print(table)


def main():
    """Generate sample logs and ingest them into Splunk HEC."""
    console = Console()
    load_dotenv()
    config = load_config()
    token = get_splunk_token(config)

    if not token or token == "PASTE_YOUR_SPLUNK_TOKEN_HERE":
        console.print("[red]SPLUNK_TOKEN is missing. Set it in .env before running.[/red]")
        return

    scenarios = {
        "Brute Force Attack": generate_brute_force_events(),
        "Suspicious PowerShell": generate_powershell_events(),
        "Data Exfiltration Pattern": generate_exfiltration_events(),
    }

    summary = {}
    for scenario, events in scenarios.items():
        summary[scenario] = ingest_events(events, token, console)

    print_summary(summary, console)


if __name__ == "__main__":
    main()
