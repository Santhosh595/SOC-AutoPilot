import os
import re
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table


class Reporter:
    """Save investigation artifacts and print Rich investigation summaries."""

    def __init__(self, reports_dir="./reports"):
        """Create the reports directory and initialize console output."""
        self.reports_dir = reports_dir
        os.makedirs(self.reports_dir, exist_ok=True)
        self.console = Console()

    def save_markdown_report(self, report_content: str, prefix="investigation") -> str:
        """Save markdown report content and return the full file path."""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"{prefix}_{timestamp}.md"
        file_path = os.path.join(self.reports_dir, filename)

        with open(file_path, "w", encoding="utf-8") as report_file:
            report_file.write(report_content)

        return file_path

    def save_spl_rule(self, spl_content: str, alert_name: str) -> str:
        """Save a Splunk SPL detection rule and return the full file path.

        Returns None without writing a file when spl_content is empty.
        """
        if not spl_content or not spl_content.strip():
            return None
        sanitized_alert_name = self._sanitize_filename(alert_name)
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"detection_{sanitized_alert_name}_{timestamp}.spl"
        file_path = os.path.join(self.reports_dir, filename)

        with open(file_path, "w", encoding="utf-8") as spl_file:
            spl_file.write(spl_content)

        return file_path

    def print_summary_table(
        self,
        classification: dict,
        iocs: dict,
        similar_cases: list,
        threat_enrichment: dict | None = None,
    ):
        """Print a Rich panel containing the investigation summary table."""
        table = Table()
        table.add_column("Field", style="cyan")
        table.add_column("Value")
        table.add_row("Verdict", self._colored_verdict(classification.get("verdict")))
        table.add_row("Severity", str(classification.get("severity", "UNKNOWN")))
        table.add_row("Confidence", self._format_confidence(classification.get("confidence")))
        table.add_row("Threat Type", str(classification.get("threat_type", "Unknown")))
        table.add_row(
            "Recommended Action",
            str(classification.get("recommended_action", "No action provided.")),
        )
        table.add_row(
            "Threat Intel",
            self._format_threat_intel_row(threat_enrichment),
        )

        self.console.print(Panel(table, title="Investigation Summary"))

        if similar_cases:
            self.console.print(
                f"[yellow]Similar Past Cases Found: {len(similar_cases)}[/yellow]"
            )

        found_iocs = self._format_iocs(iocs)
        if found_iocs:
            self.console.print("IOCs Found:")
            for label, values in found_iocs:
                self.console.print(f"- {label}: {', '.join(values)}")

    def _sanitize_filename(self, value: str) -> str:
        """Replace spaces and special characters with underscores for filenames."""
        sanitized = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_")
        return sanitized or "alert"

    def _colored_verdict(self, verdict):
        """Return a Rich-colored verdict string."""
        verdict = str(verdict or "NEEDS_REVIEW")
        colors = {
            "MALICIOUS": "red",
            "NEEDS_REVIEW": "yellow",
            "FALSE_POSITIVE": "green",
        }
        color = colors.get(verdict, "white")
        return f"[{color}]{verdict}[/{color}]"

    def _format_confidence(self, confidence):
        """Format a confidence score as a percentage string."""
        try:
            return f"{float(confidence) * 100:.0f}%"
        except (TypeError, ValueError):
            return "0%"

    def _format_iocs(self, iocs):
        """Return non-empty IOC groups for summary output."""
        labels = {
            "ip_addresses": "IP Addresses",
            "usernames": "Usernames",
            "domains": "Domains",
        }
        found = []
        for key, label in labels.items():
            values = iocs.get(key, []) if isinstance(iocs, dict) else []
            if values:
                found.append((label, [str(value) for value in values]))
        return found

    def _format_threat_intel_row(self, threat_enrichment: dict | None) -> str:
        """Build a compact summary string for the Threat Intel table row."""
        if not threat_enrichment:
            return "[dim]No data[/dim]"

        _emoji = {
            "HIGHLY MALICIOUS": "🔴",
            "MALICIOUS": "🟠",
            "SUSPICIOUS": "🟡",
            "CLEAN": "🟢",
            "UNKNOWN": "⚪",
        }

        parts = []
        for ip, info in threat_enrichment.items():
            level = info.get("threat_level", "UNKNOWN")
            emoji = _emoji.get(level, "⚪")
            score = info.get("abuse_confidence_score", 0)
            parts.append(f"{emoji} {ip} ({score}/100)")

        return " | ".join(parts) if parts else "[dim]No data[/dim]"
