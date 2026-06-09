import argparse
import os

import yaml
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from agent import AutoPilotAgent, KnowledgeBase, SplunkMCPClient


console = Console()


def load_config(config_path="config.yaml") -> dict:
    """Load YAML project configuration from disk."""
    if not os.path.exists(config_path):
        return {}

    with open(config_path, "r", encoding="utf-8") as config_file:
        return yaml.safe_load(config_file) or {}


def build_parser() -> argparse.ArgumentParser:
    """Create and configure the SOC AutoPilot CLI parser."""
    parser = argparse.ArgumentParser(
        description="SOC AutoPilot v1.0 | Splunk Security Agent"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    investigate_parser = subparsers.add_parser(
        "investigate",
        help="Investigate a security alert",
    )
    investigate_parser.add_argument(
        "alert",
        help="Alert description as a string",
    )

    feedback_parser = subparsers.add_parser(
        "feedback",
        help="Add analyst feedback to an investigation",
    )
    feedback_parser.add_argument("--id", type=int, required=True)
    feedback_parser.add_argument("--verdict", type=str, required=True)
    feedback_parser.add_argument("--note", type=str, required=True)

    subparsers.add_parser(
        "test",
        help="Test Splunk connectivity",
    )
    subparsers.add_parser(
        "history",
        help="Show the last 10 investigations",
    )

    return parser


def run_investigate(config: dict, alert: str):
    """Run an investigation for the provided alert description."""
    console.print(Panel("SOC AutoPilot v1.0 | Splunk Security Agent"))
    agent = AutoPilotAgent(config)
    result = agent.investigate(alert)
    report_path = result.get("report_path") or "No report path generated"
    console.print(f"[green]Report saved to: {report_path}[/green]")


def run_test(config: dict):
    """Test the configured Splunk connection."""
    client = SplunkMCPClient(config)
    success = client.test_connection()
    if success:
        console.print("[green]Splunk connection test passed[/green]")
    else:
        console.print("[red]Splunk connection test failed[/red]")


def run_history():
    """Print the last 10 investigations from the knowledge base."""
    knowledge_base = KnowledgeBase()
    cursor = knowledge_base.conn.cursor()
    cursor.execute(
        """
        SELECT id, timestamp, verdict, severity, alert_description
        FROM investigations
        ORDER BY id DESC
        LIMIT 10
        """
    )
    rows = cursor.fetchall()

    table = Table(title="Last 10 Investigations")
    table.add_column("ID", style="cyan")
    table.add_column("Time")
    table.add_column("Verdict")
    table.add_column("Severity")
    table.add_column("Alert")

    for row in rows:
        alert = row["alert_description"] or ""
        if len(alert) > 50:
            alert = alert[:47] + "..."
        table.add_row(
            str(row["id"]),
            str(row["timestamp"] or ""),
            str(row["verdict"] or ""),
            str(row["severity"] or ""),
            alert,
        )

    console.print(table)


def run_feedback(config: dict, investigation_id: int, note: str, verdict: str):
    """Save analyst feedback for an investigation."""
    agent = AutoPilotAgent(config)
    agent.get_feedback(investigation_id, note, verdict)


def main():
    """Run the SOC AutoPilot command-line interface."""
    load_dotenv()
    config = load_config()
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "investigate":
        run_investigate(config, args.alert)
    elif args.command == "test":
        run_test(config)
    elif args.command == "history":
        run_history()
    elif args.command == "feedback":
        run_feedback(config, args.id, args.note, args.verdict)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("[yellow]Investigation cancelled.[/yellow]")
    except Exception as error:
        console.print(f"[red]Error: {error}[/red]")
